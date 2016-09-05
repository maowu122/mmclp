'''
test
'''
from os import path, makedirs, getcwd
from datetime import datetime
import requests
import hashlib
import json
import sys
import subprocess
import zipfile
import uuid


MOJANG_API = {
    'version_manifest': 'https://launchermeta.mojang.com/mc/game/version_manifest.json',
    'objects_url': 'http://resources.download.minecraft.net',
    'authurl': 'https://authserver.mojang.com/authenticate',
}
BMCL_API = {
    'version_manifest': 'http://bmclapi2.bangbang93.com/mc/game/version_manifest.json',
    'objects_url': 'http://resources.download.minecraft.net',
    'authurl': 'https://authserver.mojang.com/authenticate',
}


class ConfigManager(dict):

    def __init__(self, config_file_path):
        dict.__init__(self)
        self.config_path = path.abspath(config_file_path)
        self.read()

    def read(self):
        try:
            with open(self.config_path, 'r') as f:
                self.update(json.load(f))
        except FileNotFoundError:
            print('Not Found:' + self.config_path)

    def save(self):
        with open(self, 'w') as f:
            json.dump(self, f)
            print('Save Config!')
        self.hasChanged = False


class VersionManager():

    assets_folder_path = ''
    libraries_folder_path = ''
    version_folder_path = ''
    api = MOJANG_API
    version_manifest = None
    version_config = {}

    def __init__(self, gamepath):
        self.assets_folder_path = path.join(gamepath, 'assets')
        self.libraries_folder_path = path.join(gamepath, 'libraries')
        self.version_folder_path = path.join(gamepath, 'versions')
        self.get_version_manifest()

    def __getitem__(self, key):
        if key not in self.version_config:
            self.fetch_version_config(key)
        return self.version_config[key]

    def check_file_sha1(self, filepath, sha1String):
        with open(filepath, 'rb') as f:
            sha1obj = hashlib.sha1()
            sha1obj.update(f.read())
            hashString = sha1obj.hexdigest()
            return hashString == sha1String

    def download_file(self, url, filepath):
        http_res = requests.get(url)
        if not path.exists(path.dirname(filepath)):
            makedirs(path.dirname(filepath))
        with open(filepath, 'wb') as f:
            f.write(http_res.content)
        print('Download:' + filepath)

    def get_version_path(self, version):
        if version is None:
            raise ValueError('version is not given!')
        else:
            return path.join(self.version_folder_path, version)

    def get_version_manifest(self):
        version_manifest_file_path = path.join(self.version_folder_path, 'version_manifest.json')
        if (not path.exists(version_manifest_file_path)) or \
                datetime.fromtimestamp(path.getctime(version_manifest_file_path)).date() < datetime.today().date():
            self.download_file(self.api['version_manifest'], version_manifest_file_path)

        with open(version_manifest_file_path, 'r') as f:
            version_dict = {}
            for ver in json.load(f)['versions']:
                if ver['type'] == 'release' or ver['type'] == 'snapshot':
                    version_dict[ver['id']] = ver
            self.version_manifest = version_dict

    def fetch_version_config(self, version):
        version_json_path = path.join(self.get_version_path(version), version + '.json')
        if not path.exists(version_json_path):
            self.download_file(self.version_manifest[version]['url'], version_json_path)
        with open(version_json_path, 'r') as f:
            self.version_config[version] = json.load(f)

    def allowed_lib_list(self, version):
        for lib_info in self[version]['libraries']:
            if 'rules' in lib_info:
                isPass = True
                for rule in lib_info['rules']:
                    if rule['action'] == 'allow' and ('os' in rule and rule['os']['name'] == sys.platform):
                        isPass = False
                    elif rule['action'] == 'disallow' and rule['os']['name'] != sys.platform:
                        isPass = False
                if isPass:
                    continue

            allowed_lib = {'name': lib_info['name']}
            if 'natives' in lib_info:
                native = lib_info['natives'][sys.platform]
                downinfo = lib_info['downloads']['classifiers'][native]
            else:
                downinfo = lib_info['downloads']['artifact']
            allowed_lib['path'] = path.join(*downinfo['path'].split('/'))
            allowed_lib['url'] = downinfo['url']
            allowed_lib['sha1'] = downinfo['sha1']

            if "extract" in lib_info:
                allowed_lib['extract'] = lib_info['extract']

            yield allowed_lib

    def fetch_version_all_file(self, version):
        '''下载指定版本的所有文件'''
        version_info = self[version]

        client_down_info = version_info['downloads']['client']
        client_file_path = path.join(self.get_version_path(version), version + '-cilent.jar')
        if not (path.exists(client_file_path) and self.check_file_sha1(client_file_path, client_down_info['sha1'])):
            self.download_file(client_down_info['url'], client_file_path)

        server_down_info = version_info['downloads']['server']
        server_file_path = path.join(self.get_version_path(version), version + '-server.jar')
        if not (path.exists(server_file_path) and self.check_file_sha1(server_file_path, server_down_info['sha1'])):
            self.download_file(server_down_info['url'], server_file_path)

        asset_index = version_info['assetIndex']
        asset_index_path = path.join(self.assets_folder_path, 'indexes', asset_index['id'] + '.json')
        objects_base_path = path.join(self.assets_folder_path, 'objects')
        if not (path.exists(asset_index_path) and self.check_file_sha1(asset_index_path, asset_index['sha1'])):
            self.download_file(asset_index['url'], asset_index_path)

        with open(asset_index_path, 'r') as f:
            objects = json.load(f)['objects']
            for obj in objects:
                hash_str = objects[obj]['hash']
                obj_file_path = path.join(objects_base_path, hash_str[: 2], hash_str)
                if not (path.exists(obj_file_path) and self.check_file_sha1(obj_file_path, hash_str)):
                    obj_url = '%s/%s/%s' % (self.api['objects_url'], hash_str[: 2], hash_str)
                    self.download_file(obj_url, obj_file_path)

        for allowed_lib in self.allowed_lib_list(version):
            file_path = path.join(self.libraries_folder_path, allowed_lib['path'])
            if not (path.exists(file_path) and self.check_file_sha1(file_path, allowed_lib['sha1'])):
                self.download_file(allowed_lib['url'], file_path)

            if "extract" in allowed_lib:
                exclude_list = allowed_lib['extract']['exclude']
                if zipfile.is_zipfile(file_path):
                    zipObj = zipfile.ZipFile(file_path)
                    filelist = zipObj.namelist()
                    for filepath in filelist.copy():
                        for exclude in exclude_list:
                            if filepath.find(exclude) == 0:
                                filelist.remove(filepath)
                    zipObj.extractall(members=filelist, path=path.join(self.get_version_path(version), 'natives'))


class LoginError(Exception):
    pass


class Launcher(object):

    gamepath = '.minecraft'
    versions = {}
    user_config = None
    versions = None

    def __init__(self, gamepath):
        self.gamepath = path.abspath(gamepath)
        self.libs_folder_path = path.join(self.gamepath, 'libraries')
        self.user_config = ConfigManager(path.join(getcwd(), 'conf', 'userconf.json'))
        self.versions = VersionManager(self.gamepath)

    def login_mojang(self, email=None, password=None, clientToken=None):
        mojang_config = self.user_config['mojang']
        if email is None:
            email = mojang_config['email']
        else:
            mojang_config['email'] = email

        if password is None:
            password = mojang_config['password']
        else:
            mojang_config['password'] = password

        if clientToken is None:
            clientToken = mojang_config['clientToken']
        else:
            mojang_config['clientToken'] = clientToken

        # mojang_config['clientToken'] = uuid.uuid5(uuid.NAMESPACE_OID, self.user_config['email']).hex

        headers = {'Content-type': 'application/json'}
        postdata = {
            "agent": {"name": "Minecraft", "version": "1"},
            "username": email,
            "password": password,
            "clientToken": clientToken
        }

        res_data = requests.post(MOJANG_API['authurl'], headers=headers, data=json.dumps(postdata)).json()

        if 'availableProfiles' not in res_data:
            raise LoginError('Login Failed:' + str(res_data))

        login_result = (res_data['selectedProfile']['name'], res_data['selectedProfile']['id'], res_data['accessToken'])

        return login_result

    def run_game(self, version, java_path, user_type, playername, auth_uuid, access_token):
        version_info = self.versions[version]
        cp_list = [path.join(self.libs_folder_path, x['path']) for x in self.versions.allowed_lib_list(version)]
        cp_list.append(path.join(self.versions.get_version_path(version), version + '-cilent.jar'))
        cmd_str = '{java_path} -Djava.library.path={java_library_path} -cp {cpList} {mainClass} {minecraftArguments}'.format(
            java_path=java_path,
            java_library_path=path.join(self.versions.get_version_path(version), 'natives'),
            cpList=':'.join(cp_list),
            mainClass=version_info['mainClass'],
            minecraftArguments=version_info['minecraftArguments'].format(
                auth_player_name=playername,
                version_name=version,
                game_directory=self.gamepath,
                assets_root=self.versions.assets_folder_path,
                assets_index_name=version_info['assetIndex']['id'],
                auth_uuid=auth_uuid,
                auth_access_token=access_token,
                user_properties={},
                user_type=user_type,
                version_type=version_info['type']
            ).replace('$', '')
        )
        child = subprocess.Popen(cmd_str, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while child.poll() is None:
            line = child.stdout.readline()
            print(line.decode())
