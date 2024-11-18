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
import pandas as pd
import csv

import ast

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
    
    rebuild(package["id"])
    
    log.info('Checking resources')
    
    datasetPackage: dict[str, Any] = tk.get_action("package_show")({
                                                                      "ignore_auth": True,
                                                                      "use_cache": False,
                                                                      "validate": False,
                                                                  },
                                                                  { "id": package["id"] }
                                                                  )
                                                                  
    # TODO: maybe we should do deepcopy
    updated_package = dict(datasetPackage)
    # Keep the existing remote ID and Name
    updated_package["id"] = remote_package["id"]
    updated_package["name"] = remote_package["name"]
    updated_package["owner_org"] = remote_package["owner_org"]
      

    if 'resources' in updated_package:
        updated_package["resources"] = []                                                               

    if 'resources' in datasetPackage:
        log.info('Resources in local package found')

        for local_resource in datasetPackage["resources"]:
            
            resourceFound=False
            log.info('Checking over remote package resources')
            
            for remote_resource in remote_package["resources"]:

                if local_resource["id"] == remote_resource["id"]:
                    
                    log.info('Id of local and remote resource matched : %s', local_resource["id"])
                    resourceFound = True
                    
                    if  local_resource["url_type"] == "upload" or local_resource["datastore_active"] == True: 
                        
                        log.info('Resource type is upload')
                        
                        if  local_resource["format"] != remote_resource["format"] or local_resource["mimetype"] != remote_resource["mimetype"] or local_resource["name"] != remote_resource["name"] or   local_resource["size"] != remote_resource["size"]:
                            
                            log.info('Local resource file is changed.')   
                            
                            if local_resource["datastore_active"] == True and local_resource["format"] == "CSV":
                                local_resource["name"] += ".csv" if not name.endswith(".csv") else ""
                            
                            resourceToUpload = download_and_prepare_resource(local_resource, profile)
                            if resourceToUpload:
                                                    
                                if local_resource["datastore_active"] == True and local_resource["format"] == "CSV":
                                    resourceToUpload["mimetype"]="text/csv" 
                                    
                                remove_first_column_and_add_bom(os.path.abspath(local_resource["name"]))
                                
                                
                                ckan.action.resource_delete(id=remote_resource["id"])
                                cleaned_resource_to_upload = {k: v for k, v in resourceToUpload.items() if v not in ([])}

                      
                                resourceToSave = ckan.action.resource_create(package_id = syndicated_id,
                                                                            url = '{ckan_url}/dataset/{package_id}/resource/{id}/download/{name}'.format(
                                                                                    ckan_url=profile.ckan_url,
                                                                                    package_id=remote_resource["package_id"],
                                                                                    id=local_resource["id"],
                                                                                    name=local_resource["name"]
                                                                                    ),
                                                                            upload = open(os.path.abspath(local_resource["name"]), 'rb'),
                                                                            **cleaned_resource_to_upload)
                                
                                if local_resource["datastore_active"] == True:                        
                                    resourceUploadedToDataStore = push_csv_to_ckan_datastore(os.path.abspath(local_resource["name"]), resourceToUpload["id"], profile.ckan_url, profile.api_key)
                                    resourceToUpload["datastore_active"]= resourceUploadedToDataStore
                                    if resourceUploadedToDataStore == False:                                
                                        resourceToUpload["url_type"] ="upload"
                                                                
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
                        
                        local_res_to_upload = local_resource.copy() 
                        
                        local_res_to_upload["package_id"] = syndicated_id
                        
                        cleaned_resource_to_upload = {k: v for k, v in local_res_to_upload.items() if v not in ([])}

                        resourceToSave = ckan.action.resource_create(**cleaned_resource_to_upload)
                                                
                        updated_package["resources"].append(resourceToSave)  
                        
            if resourceFound == False:
                
                if local_resource["url_type"] == "upload" or local_resource["datastore_active"] == True:
                    
                    if local_resource["datastore_active"] == True and local_resource["format"] == "CSV":
                        local_resource["name"] += ".csv" if not local_resource["name"].endswith(".csv") else ""
                                            
                    resourceToUpload = download_and_prepare_resource(local_resource, profile)
                    if resourceToUpload:
                        
                        if local_resource["datastore_active"] == True and local_resource["format"] == "CSV":
                            resourceToUpload["mimetype"]="text/csv"
                            
                        remove_first_column_and_add_bom(os.path.abspath(local_resource["name"]))                        
                        
                        log.info("upload path %s", os.path.abspath(local_resource["name"]))

                        cleaned_resource_to_upload = {k: v for k, v in resourceToUpload.items() if v not in ([])} 
                        
                        resourceToSave = ckan.action.resource_create(package_id = syndicated_id,
                                                                    url = '{ckan_url}/dataset/{package_id}/resource/{id}/download/{name}'.format(
                                                                            ckan_url=profile.ckan_url,
                                                                            package_id=syndicated_id,
                                                                            id=local_resource["id"],
                                                                            name=local_resource["name"]
                                                                            ),
                                                                    upload = open(os.path.abspath(local_resource["name"]), 'rb'),
                                                                    **cleaned_resource_to_upload)
                        
                        resourceToUpload["url"] = resourceToSave["url"]
                                                
                        if local_resource["datastore_active"] == True:                        
                            resourceUploadedToDataStore = push_csv_to_ckan_datastore(os.path.abspath(local_resource["name"]), resourceToUpload["id"], profile.ckan_url, profile.api_key)
                            resourceToUpload["datastore_active"]= resourceUploadedToDataStore
                            if resourceUploadedToDataStore == False:                                
                                resourceToUpload["url_type"] ="upload"
                                                     
                        updated_package["resources"].append(resourceToUpload) 
                        
                        delete_local_file(local_resource["name"])
                    
                else:
                    local_res_to_upload = local_resource.copy() 
                        
                    local_res_to_upload["package_id"] = syndicated_id
                    
                    cleaned_resource_to_upload = {k: v for k, v in local_res_to_upload.items() if v not in ([])}

                    resourceToSave = ckan.action.resource_create(**cleaned_resource_to_upload)
                
                    updated_package["resources"].append(resourceToSave) 
                                                
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
    
    custom_metadata_fields = config.get('custom_metadata_fields')

    # Set custom added metadata fields in package so that it can be syndicated.
    if custom_metadata_fields:
        custom_metadata_fields = [field.strip() for field in custom_metadata_fields.split(',')]
        for field in custom_metadata_fields:
            if field.lower() not in excluded_keys:
                value = get_field_value(datasetPackage, field)
                if value and value != "[]" and value != "":  # Check if value is not None or blank
                    if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                        try:
                            # Safely convert string representation of a list into an actual list
                            value = ast.literal_eval(value)
                        except (ValueError, SyntaxError):
                            log.warning(f'Value for field {field} could not be converted to a list.')

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
    status_code  = download_file(local_resource["url"], local_resource["name"])
    
    ## Uncomment below to check in local 
    #url = 'http://localhost:5000/dataset/{package_id}/resource/{id}/download/{name}'.format(
    #    package_id=local_resource["package_id"],
    #    id=local_resource["id"],
    #    name=local_resource["name"]
    #)
    
    #status_code =download_file(url, local_resource["name"])
    
    if status_code == 200:
        resource_to_upload = remove_unnecessary_keys_for_resource_syndication(local_resource.copy())
        return resource_to_upload    
    else:
        log.error("Download failed, skipping resource preparation.")
        return None  # Return None or handle the error case accordingly

def delete_local_file(file_path):
    try:
        os.remove(file_path)
        log.info("File deleted successfully: %s", file_path)
    except OSError as e:
        log.error("Error deleting file %s: %s", file_path, e)
        
def download_file(url, local_filename):
    """Download a file from a URL and save it locally."""
    log.info("Downloading file from URL: %s", url)
    response = requests.get(url, stream=True, verify=False)
    if response.status_code == 200:
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
        log.info("File downloaded successfully: %s", local_filename)
    else:
        log.error("Failed to download file from URL: %s. Status code: %d", url, response.status_code)
     
    return response.status_code     


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

                
def remove_first_column(csv_path):
    """
    This function removes the first column from a CSV file if it exists
    and saves the file back to the given path.
    """
    try:
        # Load the CSV
        df = pd.read_csv(csv_path)

        # Check if the first column is named '_id', if so remove it
        if df.columns[0] == '_id':
            df.drop(columns=['_id'], inplace=True)

        # Save the modified dataframe back to the same file
        df.to_csv(csv_path, index=False)
    
    except Exception as e:
        log.info(f"Error while processing CSV file {csv_path}: {e}")                
        

def determine_field_type(value):
    """Determine the type of a value (text, numeric, etc.)."""
    try:
        float(value)
        return 'numeric'
    except ValueError:
        return 'text'


def remove_first_column_and_add_bom(csv_path):

    remove_first_column(csv_path) 

    # Check if BOM is present
    if not has_bom(csv_path):
        log.info("BOM not present. Writing the file with BOM...")
        write_csv_with_bom(csv_path)
        log.info(f"CSV file saved with BOM at {csv_path}.")

def check_datastore_exists(resource_id, ckan_instance_url, ckan_api_key):
    """
    Check if a datastore table already exists for the given resource_id.
    If it exists, this function returns True. Otherwise, it returns False.
    """
    datastore_search_url = f"{ckan_instance_url}/api/3/action/datastore_search"
    params = {
        'resource_id': resource_id,
        'limit': 1  # Just check if there's any data in the datastore.
    }
    headers = {'Authorization': ckan_api_key}

    try:
        response = requests.get(datastore_search_url, params=params, headers=headers)
        response_json = response.json()

        if response_json.get('success'):
            # If the datastore already contains data, it exists
            return True
        else:
            return False
    except Exception as e:
        log.info(f"Error checking datastore existence: {e}")
        return False

def create_datastore(resource_id, fields, ckan_instance_url, ckan_api_key, primary_key):
    """
    Create a datastore for the given resource_id with the specified fields.
    """
    datastore_create_url = f'{ckan_instance_url}/api/3/action/datastore_create'
    headers = {'Authorization': ckan_api_key, 'Content-Type': 'application/json'}

    # Remove '_id' field from the field list if it's included
    clean_fields = [field for field in fields if field['id'] != '_id']

    payload_create = {
        'resource_id': resource_id,
        'fields': clean_fields,  # Field definitions (columns)
        'force': True,  # Force creation even if the resource exists
        #'primary_key': primary_key
    }

    try:
        response = requests.post(datastore_create_url, json=payload_create, headers=headers)
        response.raise_for_status()
        result = response.json()

        if result.get('success'):
            log.info(f"Datastore successfully created with fields: {fields}")
            return True
        else:
            log.info(f"Failed to create datastore. Response: {result}")
            return False
    except Exception as e:
        log.info(f"Error creating datastore: {e}")
        return False
        
def delete_datastore(resource_id, ckan_instance_url, ckan_api_key):
    """
    Create a datastore for the given resource_id with the specified fields.
    """
    datastore_delete_url = f'{ckan_instance_url}/api/3/action/datastore_delete'
    headers = {'Authorization': ckan_api_key, 'Content-Type': 'application/json'}

    payload_delete = {
        'resource_id': resource_id,      
        'force': True,  # Force creation even if the resource exists    
    }

    try:
        response = requests.post(datastore_delete_url, json=payload_delete, headers=headers)
        response.raise_for_status()
        result = response.json()

        if result.get('success'):
            log.info(f"Datastore successfully deleted for resourceid: {resource_id}")
            return True
        else:
            log.info(f"Failed to deleted datastore. Response: {result}")
            return False
    except Exception as e:
        log.info(f"Error deleting datastore: {e}")
        return False        

def upsert_records(resource_id, records, ckan_instance_url, ckan_api_key, primary_key):
    """
    Insert or update records in the datastore for the given resource_id.
    """
    datastore_upsert_url = f'{ckan_instance_url}/api/3/action/datastore_upsert'
    headers = {'Authorization': ckan_api_key, 'Content-Type': 'application/json'}

    log.info(f"primary-key - {primary_key}")

    payload_upsert = {
        'resource_id': resource_id,  # The resource ID to push data to
        'method': 'insert',          # 'upsert' allows you to insert or update data
        'records': records,           # The actual CSV data as records
        'force':True,
      #  'primary_key': primary_key   # only need to be passed when method is upsert
    }

    try:
        response = requests.post(datastore_upsert_url, json=payload_upsert, headers=headers)
        response.raise_for_status()
        result = response.json()

        if result.get('success'):
            log.info(f"Successfully pushed {len(records)} records to the CKAN datastore.")
            return True   
        else:
            log.info(f"Failed to upsert records: {result}")
            return False

    except requests.exceptions.RequestException as e:
        # Capture the detailed CKAN error response
        if e.response is not None:
            content = e.response.content.decode('utf-8')
            log.info(f"Error response from CKAN: {content}")
        else:
            log.info(f"Error occurred while upserting records: {e}")
        return False    

def push_csv_to_ckan_datastore(csv_file_path, resource_id, ckan_instance_url, ckan_api_key):
    """Main function to handle CSV imports to CKAN's datastore."""

    # Read the CSV file
    with open(csv_file_path, 'r') as csv_file:
        reader = csv.DictReader(csv_file)
        headers = reader.fieldnames  # Extract CSV column headers as field names

        if not headers:
            raise ValueError("CSV file has no headers or data")

        # Sample first row to determine field types
        sample_row = next(reader)  # Peek at the first row to auto-detect field types
        fields = [{'id': header, 'type': determine_field_type(sample_row[header])} for header in headers]

        # Re-read the CSV file to collect all records
        csv_file.seek(0)  # Go back to the beginning of the file
        reader = csv.DictReader(csv_file)

        # Collect CSV data as records
        records = [row for row in reader]
                
        primary_key = check_for_primary_key(headers)


    # Step 1: Check if the datastore already exists for this resource
    datastore_exists = check_datastore_exists(resource_id, ckan_instance_url, ckan_api_key)

    
    if not datastore_exists:
        # Step 2a: If datastore doesn't exist, create it
        log.info("Datastore does not exist. Creating a new datastore.")
        created = create_datastore(resource_id, fields, ckan_instance_url, ckan_api_key, primary_key)
        if not created:
            log.info("Failed to create datastore. Exiting.")
            return
    else:        
        log.info("Datastore already exists. Proceeding to delete datastore and recreate.")
        isDatastoreDeleted = delete_datastore(resource_id, ckan_instance_url, ckan_api_key)
        if isDatastoreDeleted:
            created = create_datastore(resource_id, fields, ckan_instance_url, ckan_api_key, primary_key)
            if not created:
                log.info("Failed to create datastore. Exiting.")
                return

    # Step 2b: Insert or update records into the datastore
    isSuccess = upsert_records(resource_id, records, ckan_instance_url, ckan_api_key, primary_key)                     
    
    return isSuccess
        
        
def check_for_primary_key(headers):
    """
    Dynamic check to determine a suitable primary key column.
    Returns the primary key if found, otherwise None.
    """
    # Check if certain standard primary key fields exist, such as 'id', 'record_id', etc.
    primary_key_candidates = ['id', 'record_id', 'unique_id', 'Index', 'index']

    # Find if any of the primary key candidates exist in the headers
    for key in primary_key_candidates:
        if key in headers:
            return [key]  # Return as a list since primary_key is always passed as a list

    # If no primary key candidate is found, return None
    return None        
    
# Function to check if a file has a BOM
def has_bom(csv_file_path):
    with open(csv_file_path, 'rb') as file:
        first_bytes = file.read(3)  # Read the first 3 bytes (size of BOM)
        return first_bytes == b'\xef\xbb\xbf'  # Check for BOM signature

# Function to read data from the non-BOM file and write it back with BOM
def write_csv_with_bom(csv_file_path):
    # Read the data from the original file (without BOM)
    with open(csv_file_path, mode='r', encoding='utf-8', newline='') as file:
        reader = csv.reader(file)
        data = list(reader)  # Convert CSV reader object to a list

    # Write the CSV data with BOM
    with open(csv_file_path, mode='w', encoding='utf-8-sig', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)
    