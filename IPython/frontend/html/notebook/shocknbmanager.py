"""A notebook manager that uses Shock storage.
https://github.com/MG-RAST/Shock

Authors:

* Travis Harrison
"""

#-----------------------------------------------------------------------------
#  Copyright (C) 2012  The IPython Development Team
#
#  Distributed under the terms of the BSD License.  The full license is in
#  the file COPYING, distributed as part of this software.
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------------

import cStringIO
import datetime
import requests
import json
import dateutil.parser
from collections import defaultdict

from tornado import web

from .nbmanager import NotebookManager
from IPython.nbformat import current
from IPython.utils.traitlets import Unicode, Instance

#-----------------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------------

class ShockNotebookManager(NotebookManager):

    shock_url   = Unicode('', config=True, help='Shock server url')
    shock_auth  = Unicode('', config=True, help="Shock authentication mode. Must be 'basic' or 'globus'")
    user_name   = Unicode('', config=True, help='Shock user login name. For basic auth')
    user_passwd = Unicode('', config=True, help='Shock user login password. For basic auth')
    user_token  = Unicode('', config=True, help='Globus user bearer token. For globus auth. Used multi user authentication')
    ipynb_token = Unicode('', config=True, help='Globus ipython admin bearer token. For globus auth. Used for single or multi user authentication.')
    user_email  = None
    node_type   = 'ipynb'
    shock_map   = {}
    get_auth    = {}
    post_auth   = {}

    def __init__(self, **kwargs):
        """verify Shock Auth mode and proper auth credintals for that mode, set auth GET/POST format"""
        super(ShockNotebookManager, self).__init__(**kwargs)
        if not (self.shock_auth == 'basic' or self.shock_auth == 'globus'):
            raise web.HTTPError(412, u"Invalid Shock Authentication mode (%s). Choose 'basic' or 'globus'." %self.shock_auth)
        if self.user_name and self.user_passwd and self.shock_auth == 'basic':
            self.get_auth = {'auth': (self.user_name, self.user_passwd)}
            self.post_auth = {'auth': (self.user_name, self.user_passwd)}
        elif self.user_token and self.ipynb_token and self.shock_auth == 'globus':
            self.get_auth = {'headers': {'Authorization': 'OAuth %s'%self.user_token}}
            self.post_auth = {'headers': {'Authorization': 'OAuth %s'%self.ipynb_token}}
            self.user_email = self._get_goauth(self.user_token, 'email')
        elif self.ipynb_token and self.shock_auth == 'globus':
            self.get_auth = {'headers': {'Authorization': 'OAuth %s'%self.ipynb_token}}
            self.post_auth = {'headers': {'Authorization': 'OAuth %s'%self.ipynb_token}}
        else:
            raise web.HTTPError(412, u"Missing credintals for Shock Authentication mode (%s)."%self.shock_auth)

    def set_notebook_names(self):
        """load the notebook ids and names from Shock.
        The uuid and name are stored as Shock metadata.
            1. Skip nb nodes with no files
            2. Skip nb nodes tagged as 'deleted'
            3. If multiple nb with same uuid, get latest timestamp
        """
        self.mapping = {}
        self.shock_map = {}
        nb_vers = defaultdict(list)
        
        query_path = '?querynode&type='+self.node_type
        query_result = self._get_shock_node(query_path, 'json')
        
        if query_result is not None:
            for node in query_result:
                if node['file']['size'] and ('nbid' in node['attributes']) and node['attributes']['nbid'] and ('name' in node['attributes']) and node['attributes']['name']:
                    nb_vers[ node['attributes']['nbid'] ].append(node)

        # only get listing of latest for each notebook uuid set
        for uuid in nb_vers.iterkeys():
            nodes = sorted(nb_vers[uuid], key=lambda x: x['attributes']['created'], reverse=True)
            # if latest is flaged deleted - don't show
            if ('deleted' in nodes[0]['attributes']) and nodes[0]['attributes']['deleted']:
                continue
            self.mapping[uuid] = nodes[0]['attributes']['name']
            self.shock_map[uuid] = nodes[0]

    def list_notebooks(self):
        """List all notebooks in the container.
        This version uses `self.mapping` as the authoritative notebook list.
        """
        self.set_notebook_names()
        data = [dict(notebook_id=uuid,name=name) for uuid, name in self.mapping.items()]
        data = sorted(data, key=lambda item: item['name'])
        return data

    def delete_notebook_id(self, notebook_id):
        """Delete a notebook's id in the mapping.
        This doesn't delete the actual notebook, only its entry in the mapping.
        """
        del self.mapping[notebook_id]
        del self.shock_map[notebook_id]

    def notebook_exists(self, notebook_id):
        """Does a notebook exist?"""
        if (notebook_id in self.mapping) and (notebook_id in self.shock_map):
            return True
        else:
            return False

    def read_notebook_object(self, notebook_id):
        """Get the object representation of a notebook by notebook_id."""
        if not self.notebook_exists(notebook_id):
            raise web.HTTPError(404, u'Notebook does not exist: %s' %notebook_id)
        try:
            node_path = '/%s?download' %self.shock_map[notebook_id]['id']
            node_data = self._get_shock_node(node_path, 'data')
        except:
            raise web.HTTPError(500, u'Notebook cannot be read')
        try:
            # v1 and v2 and json in the .ipynb files.
            nb = current.reads(node_data, u'json')
        except:
            raise web.HTTPError(500, u'Unreadable JSON notebook.\n%s' %node_data)
        dt = self.shock_map[notebook_id]['attributes']['created']
        last_modified = dateutil.parser.parse(dt) if dt else datetime.datetime.utcnow().isoformat()
        return last_modified, nb

    def write_notebook_object(self, nb, notebook_id=None):
        """Save an existing notebook object by notebook_id."""
        try:
            new_name = nb.metadata.name
        except AttributeError:
            raise web.HTTPError(400, u'Missing notebook name')
        try:
            if notebook_id is None:
                notebook_id = self.new_notebook_id(new_name)
            if not hasattr(nb.metadata, 'type'):
                nb.metadata.type = 'generic'
            if not hasattr(nb.metadata, 'description'):
                nb.metadata.description = ''
            nb.metadata.created = datetime.datetime.utcnow().isoformat()
            nb.metadata.nbid = notebook_id
        except Exception as e:
            raise web.HTTPError(400, u'Unexpected error setting notebook attributes: %s' %e)
        if notebook_id not in self.mapping:
            raise web.HTTPError(404, u'Notebook does not exist: %s' %notebook_id)

        try:
            data = json.dumps(nb)
            attr = json.dumps(nb.metadata)
            shock_node = self._post_shock_node(new_name, data, attr)
        except Exception as e:
            raise web.HTTPError(400, u'Unexpected error while saving notebook: %s' %e)

        self.mapping[notebook_id] = new_name
        self.shock_map[notebook_id] = shock_node
        return notebook_id

    def delete_notebook(self, notebook_id):
        """Delete notebook by notebook_id.
        Currently can not delete in shock,
        instead we create a new copy flagged as deleted"""
        if not self.notebook_exists(notebook_id):
            raise web.HTTPError(404, u'Notebook does not exist: %s' %notebook_id)
        last_modified, nb = self.read_notebook_object(notebook_id)
        nb.metadata['deleted'] = 1;
        self.write_notebook_object(nb, notebook_id)
        self.delete_notebook_id(notebook_id)

    def _get_goauth(self, token, key=None):
        name = token.split('|')[0].split('=')[1]
        gurl = "https://nexus.api.globusonline.org/users/"+name
        try:
            rget = requests.get(url, headers={'Authorization': 'Globus-Goauthtoken %s'%token})
        except Exception as e:
            raise web.HTTPError(504, u'Unable to connect to Globus server %s: %s' %(url, e))
        if not (rget.ok and rget.text):
            raise web.HTTPError(504, u'Unable to connect to Globus server %s: %s' %(url, rget.raise_for_status()))
        rj = rget.json
        if not (rj and isinstance(rj, dict)):
            raise web.HTTPError(415, u'Return data not valid JSON format: %s' %e)
        return rj[key] if key and key in rj else rj

    def _get_shock_node(self, path, format):
        url = self.shock_url+'/node'+path
        content = None
        try:
            rget = requests.get(url, **self.get_auth)
        except Exception as e:
            raise web.HTTPError(504, u'Unable to connect to Shock server %s: %s' %(url, e))
        if not (rget.ok and rget.text):
            raise web.HTTPError(504, u'Unable to connect to Shock server %s: %s' %(url, rget.raise_for_status()))
        if format == 'json':
            rj = rget.json
            if not (rj and isinstance(rj, dict) and all([key in rj for key in ['S','D','E']])):
                raise web.HTTPError(415, u'Return data not valid Shock format: %s' %e)
            if rj['E']:
                raise web.HTTPError(rj['S'], 'Shock error: '+rj['E'])
            return rj['D']
        else:
            return rget.text

    def _post_shock_node(self, name, data, attr):
        url = self.shock_url+'/node'
        data_hdl = cStringIO.StringIO(data)
        attr_hdl = cStringIO.StringIO(attr)
        files = { "upload": ('%s.ipynb'%name, data_hdl), "attributes": ('%s_metadata.json'%name, attr_hdl) }
        try:
            kwargs = {'files': files, 'data': {'datatype': self.node_type}}
            kwargs.update(self.post_auth)
            rpost = requests.post(url, **kwargs)
            rj = rpost.json
        except Exception as e:
            raise web.HTTPError(504, u'Unable to connect to Shock server %s: %s' %(url, e))
        if not (rpost.ok and rj and isinstance(rj, dict) and all([key in rj for key in ['S','D','E']])):
            raise web.HTTPError(500, u'Unable to POST to Shock server %s: %s' %(url, rpost.raise_for_status()))
        if rj['E']:
            raise web.HTTPError(rj['S'], 'Shock error: '+rj['E'])
        # running in globus multi-user auth mode
        # we need to add the user to node read/write ACLs
        if self.user_token and self.user_email and self.shock_auth == 'globus':
            self._put_shock_acl(rj['D']['id'], ['read', 'write'], self.user_email)
        return rj['D']

    def _put_shock_acl(self, node, modes, email):
        url = '%s/node/%s/acl' %(self.shock_url, node)
        try:
            kwargs = {'params': {}}
            for m in modes:
                kwargs['params'][m] = email
            kwargs.update(self.post_auth)
            rput = requests.put(url, **kwargs)
            rj = rput.json
        except Exception as e:
            raise web.HTTPError(504, u'Unable to connect to Shock server %s: %s' %(url, e))
        if not (rput.ok and rj and isinstance(rj, dict) and all([key in rj for key in ['S','D','E']])):
            raise web.HTTPError(500, u'Unable to PUT to Shock server %s: %s' %(url, rput.raise_for_status()))
        if rj['E']:
            raise web.HTTPError(rj['S'], 'Shock error: '+rj['E'])
        return

    def log_info(self):
        self.log.info("Serving notebooks from Shock storage %s" %self.shock_url)
