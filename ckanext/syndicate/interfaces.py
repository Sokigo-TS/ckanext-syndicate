from __future__ import annotations

import logging
from typing import Any
from werkzeug.utils import import_string
import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan.plugins import Interface

from ckan.common import config

from .types import Profile

log = logging.getLogger(__name__)


class ISyndicate(Interface):
    def skip_syndication(
        self, package: model.Package, profile: Profile
    ) -> bool:
        """Decide whether a package must NOT be syndicated.

        Return `True` if package does not need syndication. Keep in mind, that
        non-syndicated package remains the same on the remote side. If package
        was removed locally, it's better not to skip syndication, so that it
        can be removed from the remote side.

        """
        
        log.info('skip_syndication called')
        
        if package.private:
            return True
                
        if profile.predicate:
            predicate = import_string(profile.predicate)
            if not predicate(package):
                log.info(
                    "Dataset[{}] will not syndicate because of predicate[{}]"
                    " rejection".format(package.id, profile.predicate)
                )
                return True
        
        group_present_for_automatic_syndicate = False
        try:
            params = {
            "id": package.id,
            }
            datasetPackage: dict[str, Any] = tk.get_action("package_show")(
                {
                    "ignore_auth": True,
                    "use_cache": False,
                    "validate": False,
                },
                params,
            )
            
            groupNameForAutomaticSyndication = config.get('groupname_automaticsyndication')
            
            if datasetPackage and groupNameForAutomaticSyndication:
                log.info('Checking groups for automatic syndication for package: %s', package.id)
                if 'groups' in datasetPackage:
                    groups = datasetPackage['groups']
                    for group in groups:
                        if 'name' in group and group['name'].lower() == groupNameForAutomaticSyndication.lower():
                            group_present_for_automatic_syndicate = True;
                            break
                    if not group_present_for_automatic_syndicate:
                        log.info('No group with name %s found in package %s for automatic syndication', groupNameForAutomaticSyndication , package.id)                
            else:
                log.warning('No package found to check groups.')

        except Exception as e:     
            log.error('Error occurred while checking the group name existence for automatic syndication %s', e)        
        
        return not group_present_for_automatic_syndicate
                   
        ### Commented below code as syndication will work through only group name.
        #syndicate = tk.asbool(package.extras.get(profile.flag, "false"))
        #log.info('syndicate value from flag %s.', syndicate) 
        #return not syndicate

    def prepare_package_for_syndication(
        self, package_id: str, data_dict: dict[str, Any], profile: Profile
    ) -> dict[str, Any]:
        """Make modifications of the dict that will be sent to remote portal.

        Remove all the sensitive fields, normalize package type, etc.

        """
        return data_dict
