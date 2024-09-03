from __future__ import annotations

import contextlib
import logging
import uuid
from typing import Any, Optional

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
import ckanapi
import requests
from ckan import model
from ckan.lib.search import rebuild

from ckanext.syndicate.interfaces import ISyndicate

from . import signals
from .types import Profile, Topic
from .utils import deprecated

from ckan.common import config

import os

log = logging.getLogger(__name__)
import json

def get_target(url, apikey):
    ckan = ckanapi.RemoteCKAN(url, apikey=apikey)
    return ckan


def sync_package(package_id: str, action: Topic, profile: Profile):
    log.info(
        "Sync package %s, with action %s to the %s",
        package_id,
        action.name,
        profile.id,
    )

    # load the package at run of time task (rather than use package state at
    # time of task creation).
    params = {
        "id": package_id,
    }
    package: dict[str, Any] = tk.get_action("package_show")(
        {
            "ignore_auth": True,
            "use_cache": False,
            "validate": False,
        },
        params,
    )

    ## Commenting but can be used in future.
    #set_syndicate_flag(package["id"], profile)
 
    _notify_before(package_id, profile, params)

    if action is Topic.create:
        _create(package, profile)
    elif action is Topic.update:
        _update(package, profile)


    _notify_after(package_id, profile, params)


def _notify_before(package_id, profile, params):
    try:
        tk.get_action("before_syndication_action")(
            {"profile": profile}, params
        )
    except KeyError:
        pass
    else:
        deprecated(
            "before_syndication_action is deprecated. Use before_syndication"
            " signal instead"
        )
    signals.before_syndication.send(package_id, profile=profile, params=params)


def _notify_after(package_id, profile, params):
    try:
        tk.get_action("after_syndication_action")({"profile": profile}, params)
    except KeyError:
        pass
    else:
        deprecated(
            "after_syndication_action is deprecated. Use after_syndication"
            " signal instead"
        )
    signals.after_syndication.send(package_id, profile=profile, params=params)


def replicate_remote_organization(org: dict[str, Any], profile: Profile):
    ckan = get_target(profile.ckan_url, profile.api_key)
    remote_org = None

    if org is None:
        return None

    try:
        remote_org = ckan.action.organization_show(id=org["name"])
    except ckanapi.NotFound:
        log.error(
            "Organization %s not found, creating new Organization.",
            org["name"],
        )
    except (ckanapi.NotAuthorized, ckanapi.CKANAPIError) as e:
        log.error("Replication error(trying to continue): {}".format(e))
    except Exception as e:
        log.error("Replication error: {}".format(e))
        raise

    if not remote_org:
        org.pop("id")
        org.pop("image_url", None)
        org.pop("num_followers", None)
        org.pop("tags", None)
        org.pop("users", None)
        org.pop("groups", None)

        default_img_url = (
            "https://www.gravatar.com/avatar/123?s=400&d=identicon"
        )
        image_url = org.pop("image_display_url", default_img_url)
        image_fd = requests.get(image_url, stream=True, timeout=2).raw
        org.update(image_upload=image_fd)

        remote_org = ckan.action.organization_create(**org)

    return remote_org["id"]


def _create(package: dict[str, Any], profile: Profile):

    if "state" in package and package["state"] == "draft":
        return

    ckan = get_target(profile.ckan_url, profile.api_key)

    # Create a new package based on the local instance
    new_package_data = dict(package)
    del new_package_data["id"]

    new_package_data["name"] = _compute_remote_name(package, profile)

    new_package_data = _prepare(package["id"], new_package_data, profile)
   
    new_package_data['extras'] = []
   
    with reattaching_context(package["id"], new_package_data, profile, ckan):
        remote_package = ckan.action.package_create(**new_package_data)      
     
                
    set_syndicated_id(
        package["id"],
        remote_package["id"],
        profile.field_id,
    )


def _update(package: dict[str, Any], profile: Profile):
    ckan = get_target(profile.ckan_url, profile.api_key)

    syndicated_id: Optional[str] = tk.h.get_pkg_dict_extra(
        package, profile.field_id
    )
    
    log.info("SyndicateId %s",syndicated_id)

    
    if not syndicated_id:
        return _create(package, profile)
    try:
        remote_package = ckan.action.package_show(id=syndicated_id)
    except ckanapi.NotFound:
        return _create(package, profile)

    # TODO: maybe we should do deepcopy
    updated_package = dict(package)
    # Keep the existing remote ID and Name
    updated_package["id"] = remote_package["id"]
    updated_package["name"] = remote_package["name"]
    updated_package["owner_org"] = remote_package["owner_org"]
      

    if 'resources' in updated_package:
        updated_package["resources"] = []
    
    log.info('Checking resources')
    
    datasetPackage: dict[str, Any] = tk.get_action("package_show")({
                                                                      "ignore_auth": True,
                                                                      "use_cache": False,
                                                                      "validate": False,
                                                                  },
                                                                  { "id": package["id"] }
                                                                  )

    if 'resources' in datasetPackage:
        log.info('Resources in local package found')

        for local_resource in datasetPackage["resources"]:
            
            resourceFound=False
            log.info('Checking over remote package resources')
            
            for remote_resource in remote_package["resources"]:

                if local_resource["id"] == remote_resource["id"]:
                    
                    log.info('Id of local and remote resource matched : %s', local_resource["id"])
                    resourceFound = True
                    
                    if  local_resource["url_type"] == "upload": 
                        
                        log.info('Resource type is upload')
                        
                        if  local_resource["format"] != remote_resource["format"] or local_resource["mimetype"] != remote_resource["mimetype"] or local_resource["name"] != remote_resource["name"] or   local_resource["size"] != remote_resource["size"]:
                            
                            log.info('Local resource file is changed.')   
                            
                            resourceToUpload = download_and_prepare_resource(local_resource, profile)
                           
                            ckan.action.resource_delete(id=remote_resource["id"])
                            
                            resourceToSave = ckan.action.resource_create(package_id = syndicated_id,
                                                                        url = '{ckan_url}/dataset/{package_id}/resource/{id}/download/{name}'.format(
                                                                                ckan_url=profile.ckan_url,
                                                                                package_id=remote_resource["package_id"],
                                                                                id=local_resource["id"],
                                                                                name=local_resource["name"]
                                                                                ),
                                                                        upload = open(os.path.abspath(local_resource["name"]), 'rb'),
                                                                        **resourceToUpload)
                            
                           
                            resourceToUpload["url"] = resourceToSave["url"]

                            updated_package["resources"].append(resourceToUpload)
                            
                            delete_local_file(local_resource["name"])
                             
                        else:
                            
                            log.info('Local resource metadata modified date is not greater than remote') 
                            localResourceToUpload = local_resource
                            localResourceToUpload["url"] = remote_resource["url"]
                            localResourceToUpload["package_id"] = remote_resource["package_id"]
                            
                            updated_package["resources"].append(localResourceToUpload)   

                    else:
                        log.info('Resource type is not of upload')
                                                
                        ckan.action.resource_delete(id=remote_resource["id"])
                        updated_package["resources"].append(local_resource)  
                        
            if resourceFound == False:
                if local_resource["url_type"] == "upload":
                    
                    resourceToUpload = download_and_prepare_resource(local_resource, profile)
    
                    log.info("upload path %s", os.path.abspath(local_resource["name"]))
    
                    resourceToSave = ckan.action.resource_create(package_id = syndicated_id,
                                                                url = '{ckan_url}/dataset/{package_id}/resource/{id}/download/{name}'.format(
                                                                        ckan_url=profile.ckan_url,
                                                                        package_id=syndicated_id,
                                                                        id=local_resource["id"],
                                                                        name=local_resource["name"]
                                                                        ),
                                                                upload = open(os.path.abspath(local_resource["name"]), 'rb'),
                                                                **resourceToUpload)
                    
                    resourceToUpload["url"] = resourceToSave["url"]
    
                    updated_package["resources"].append(resourceToUpload) 
                    
                    delete_local_file(local_resource["name"])
                    
                else:
                    updated_package["resources"].append(local_resource) 
                                                
    else: 
        if 'resources' in remote_package:
            for resource in remote_package["resources"]:
                ckan.action.resource_delete(id=resource["id"])

      
    extras_to_syndicate = []  
      
    updated_package_extras = [] 
    if 'extras' in datasetPackage:
        updated_package_extras = datasetPackage['extras']
    
    # First step: Process keys from remote_package["extras"]

    if 'extras' in remote_package:        
        for remote_extra in remote_package["extras"]:
            remote_key = remote_extra['key']
            remote_value = remote_extra['value']
            
            if remote_key in updated_package_extras:
                updated_value = next((extra['value'] for extra in updated_package_extras if extra['key'] == remote_key), None)
                # If key exists, update the value
                extras_to_syndicate[remote_key]['value'] = updated_value
            else:
                # If key doesn't exist, add the new key-value pair
                extras_to_syndicate.append(remote_extra)
    
    remote_keys = set()
    
    # Second step: Process keys from updated_package_extras that are not in remote_package["extras"]
    if 'extras' in datasetPackage:
        if 'extras' in remote_package and remote_package['extras']:    
            remote_keys = {extra['key'] for extra in remote_package['extras']}  # Get all keys from remote_package
        
        for updated_extra in updated_package_extras:
            updated_key = updated_extra['key']
            
            # If the key is not in remote_package, append it to extras_to_syndicate
            if updated_key not in remote_keys:
                extras_to_syndicate.append(updated_extra)

    # Fields that should not be syndicated
    
    excluded_fields = config.get('syndicate_excluded_fields')

    if excluded_fields:
        excluded_keys = [key.lower() for key in excluded_fields.split()]
    else:
        excluded_keys = []
    
    custom_metadata_fields = [
                       'language', 'access_rights', 'source', 'status', 'frequency', 'issued',
                       'modified', 'conforms_to', 'spatial_uri', 'temporal_start', 'temporal_end',
                       'spatial_resolution_in_meters', 'provenance', 'Klassificering', 'Utgivare',
                       'publisher_uri', 'publisher_url', 'publisher_email', 'publisher_type',
                       'contact_uri', 'contact_name', 'contact_email'
    ]


    # Set custom added metadata fields in package so that it can be syndicated.
    for field in custom_metadata_fields:
        if field.lower() not in excluded_keys:
            value = get_field_value(datasetPackage, field)
            if value:  # Check if value is not None or blank
                updated_package[field] = value
       
    #Set extra variables
    updated_package['extras'] = extras_to_syndicate
    
    # Remove custom fields from extra as it will throw error i.e. Schema field with the same name already exists.
    if 'extras' in updated_package:
        extras_list = updated_package['extras']
        updated_package['extras'] = [item for item in extras_list if item.get('key')  not in custom_metadata_fields]


    with reattaching_context(package["id"], updated_package, profile, ckan):
        ckan.action.package_update(**updated_package)

 
def get_field_value(package, field):
    val = fetch_value_from_extras(package['extras'], field)
    
    val = val if val else package[field] if field in package else None
    
    return val     
   

def fetch_value_from_extras(extras_list, key):
    for item in extras_list:
        if item.get('key') == key:
            return item.get('value')
    return None

def remove_unnecessary_keys_for_resource_syndication(resource):
    for key in ["package_id", "url", "upload"]:
        if key in resource:
            resource.pop(key, None)
    return resource

def download_and_prepare_resource(local_resource, profile):
    #download_file(local_resource["url"], local_resource["name"])
    
    # Uncomment below to check in local 
    url = 'http://localhost:5000/dataset/{package_id}/resource/{id}/download/{name}'.format(
        package_id=local_resource["package_id"],
        id=local_resource["id"],
        name=local_resource["name"]
    )
    download_file(url, local_resource["name"])
    resource_to_upload = remove_unnecessary_keys_for_resource_syndication(local_resource.copy())
    return resource_to_upload        

def delete_local_file(file_path):
    try:
        os.remove(file_path)
        log.info("File deleted successfully: %s", file_path)
    except OSError as e:
        log.error("Error deleting file %s: %s", file_path, e)
        
def download_file(url, local_filename):
    """Download a file from a URL and save it locally."""
    log.info("Downloading file from URL: %s", url)
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
        log.info("File downloaded successfully: %s", local_filename)
    else:
        log.error("Failed to download file from URL: %s. Status code: %d", url, response.status_code)


def _compute_remote_name(package: dict[str, Any], profile: Profile):
    name = "%s-%s" % (
        profile.name_prefix,
        package["name"],
    )
    if len(name) > 100:
        uniq = str(uuid.uuid3(uuid.NAMESPACE_DNS, name))
        name = name[92:] + uniq[:8]
    return name


def _normalize_org_id(package: dict[str, Any], profile: Profile):
    
    org = package.pop("organization")
    if profile.replicate_organization:
        org_id = replicate_remote_organization(org, profile)
    else:
        # Take syndicated org from the profile or use global config org
        org_id = profile.organization
    return org_id


def _prepare(
    local_id: str, package: dict[str, Any], profile: Profile
) -> dict[str, Any]:

    
    extras_dict = dict([(o["key"], o["value"]) for o in package["extras"]])
    extras_dict.pop(profile.field_id, None)
    package["extras"] = [
        {"key": k, "value": v} for (k, v) in extras_dict.items()
    ]

    package["resources"] = [
        {"url": r["url"], "name": r["name"]} for r in package["resources"]
    ]
        
    package["owner_org"] = _normalize_org_id(package, profile)

    try:
        package = tk.get_action("update_dataset_for_syndication")(
            {},
            {"dataset_dict": package, "package_id": local_id},
        )
    except KeyError:
        pass
    else:
        deprecated(
            "update_dataset_for_syndication is deprecated. Implement"
            " ISyndicate instead"
        )
    for plugin in plugins.PluginImplementations(ISyndicate):
        package = plugin.prepare_package_for_syndication(
            local_id, package, profile
        )

    return package


def set_syndicated_id(local_id: str, remote_id: str, field: str):
    """Set the remote package id on the local package"""
    ext_id = (
        model.Session.query(model.PackageExtra.id)
        .join(model.Package, model.Package.id == model.PackageExtra.package_id)
        .filter(
            model.Package.id == local_id,
            model.PackageExtra.key == field,
        )
        .first()
    )
    if not ext_id:
        existing = model.PackageExtra(
            package_id=local_id,
            key=field,
            value=remote_id,
        )
        model.Session.add(existing)
        model.Session.commit()
        model.Session.flush()
    else:  
        model.Session.query(model.PackageExtra).filter(model.PackageExtra.key == ext_id[0]).update(
            {"value": remote_id, "state": "active"}
        )
                
    rebuild(local_id)

def set_syndicate_flag(local_id: str, profile: Profile):
    
    log.info("set_syndicate_flag method called")  
    
    params = {
        "id": local_id,
        }
    datasetPackage: dict[str, Any] = tk.get_action("package_show")(
        {
            "ignore_auth": True,
            "use_cache": False,
            "validate": False,
        },
        params,
    )
      
    syndicate_key_present = False  
      
    extras = datasetPackage['extras']
    for extra in extras:
        if extra['key'] == profile.flag:
            syndicate_key_present = True
            log.info('Key "syndicate" is already present in extras.')
            break
    
    log.info("syndicate_key_present : %s",syndicate_key_present)   
       
    if not syndicate_key_present:
        syndicate_key = model.PackageExtra(
            package_id=local_id,
            key=profile.flag,
            value="true",
        )
        model.Session.add(syndicate_key)
        model.Session.commit()
        model.Session.flush()   
        
        
    rebuild(local_id)

@contextlib.contextmanager
def reattaching_context(
    local_id: str,
    package: dict[str, Any],
    profile: Profile,
    ckan: ckanapi.RemoteCKAN,
):

    try:
        yield
    except ckanapi.ValidationError as e:
        if "That URL is already in use." not in e.error_dict.get("name", []):
            raise
    else:
        return
    
    log.warning(
        "There is a package with the same name on remote portal: %s.",
        package["name"],
    )
    author = profile.author
    if not author:
        log.error(
            "Profile %s does not have author set. Skip syndication", profile.id
        )
        return
        
    

    try:
        remote_package = ckan.action.package_show(id=package["name"])
    except ckanapi.NotFound:
        log.error(
            "Current user does not have access to read remote package. Skip"
            " syndication"
        )
        return

    try:
        remote_user = ckan.action.user_show(id=author)
    except ckanapi.NotFound:
        log.error(
            'User "{0}" not found on remote portal. Skip syndication'.format(
                author
            )
        )
        return

    if remote_package["creator_user_id"] != remote_user["id"]:
        log.error(
            "Creator of remote package %s did not match '%s(%s)'. Skip"
            " syndication",
            remote_package["creator_user_id"],
            author,
            remote_user["id"],
        )
        return

    log.info("Author is the same({0}). Continue syndication".format(author))

    ckan.action.package_update(**package)         
    set_syndicated_id(
        local_id,
        remote_package["id"],
        profile.field_id,
    )

@contextlib.contextmanager
def remove_syndicated_dataset(package_id: str, profile: Profile):
    log.info("removing syndicated package")

    params = {
        "id": package_id,
    }
    datasetPackage: dict[str, Any] = tk.get_action("package_show")(
        {
            "ignore_auth": True,
            "use_cache": False,
            "validate": False,
        },
        params,
    )
    
    syndicated_id_key_present = False  
    syndicated_id = None  
      
    extras = datasetPackage['extras']
    for extra in extras:
        if extra['key'] == profile.field_id:
            syndicated_id = extra['value']
            syndicated_id_key_present = True
            break
    
    log.info("syndicated_id_key_present : %s",syndicated_id_key_present)   
       
    if syndicated_id_key_present:
        ckan = get_target(profile.ckan_url, profile.api_key)
        if ckan:
            
            ckan.action.dataset_purge(id=syndicated_id)   
                
            log.info(f'Removing {profile.field_id} key ')
            
            ext_id = (
                model.Session.query(model.PackageExtra.id)
                .join(model.Package, model.Package.id == model.PackageExtra.package_id)
                .filter(
                    model.Package.id == package_id,
                    model.PackageExtra.key == profile.field_id,
                )
                .first()
            )
            
            if ext_id:
                model.Session.query(model.PackageExtra).filter(model.PackageExtra.id == ext_id[0]).delete()
                model.Session.commit()
                model.Session.flush()
                rebuild(package_id)

                
        
        