'''
一点MineCraft启动器代码，练手用的:)
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
        with open(self.config_path, 'w') as f:
            json.dump(self, f)
            print('Save Config!')


class VersionManager():

    def __init__(self, gamepath, api):
        self.assets_folder_path = path.join(gamepath, 'assets')
        self.libraries_folder_path = path.join(gamepath, 'libraries')
        self.version_folder_path = path.join(gamepath, 'versions')
        self.version_config = {}
        self.version_manifest = None
        self.latest_snapshot = None
        self.latest_release = None
        self.API = api
        self.fetch_version_manifest()

    def check_file(self, filepath, sha1_string):
        '''检查文件是否存在以及sha1是否正确'''
        if path.exists(filepath):
            with open(filepath, 'rb') as f:
                sha1obj = hashlib.sha1()
                sha1obj.update(f.read())
                if sha1_string == sha1obj.hexdigest():
                    return True
        return False

    def download_file(self, url, filepath):
        http_res = requests.get(url)
        if not path.exists(path.dirname(filepath)):
            makedirs(path.dirname(filepath))
        with open(filepath, 'wb') as f:
            f.write(http_res.content)
        print('Download:' + filepath)

    def get_version_dict(self, key):
        if key not in self.version_config:
            self.fetch_version_config(key)
        return self.version_config[key]

    def get_version_path(self, version):
        if version is None:
            raise ValueError('version is not given!')
        else:
            return path.join(self.version_folder_path, version)

    def fetch_version_manifest(self):
        version_manifest_file_path = path.join(self.version_folder_path, 'version_manifest.json')
        if not (path.exists(version_manifest_file_path) and
                datetime.fromtimestamp(path.getctime(version_manifest_file_path)).date() < datetime.today().date()):
            self.download_file(self.api['version_manifest'], version_manifest_file_path)

        with open(version_manifest_file_path, 'r') as f:
            version_dict = {}
            data = json.load(f)
            self.latest_snapshot = data['latest']['snapshot']
            self.latest_release = data['latest']['release']
            for ver in data['versions']:
                if ver['type'] == 'release' or ver['type'] == 'snapshot':
                    version_dict[ver['id']] = ver
            self.version_manifest = version_dict

    def fetch_version_config(self, version):
        version_json_path = path.join(self.get_version_path(version), version + '.json')
        if not path.exists(version_json_path):
            self.download_file(self.version_manifest[version]['url'], version_json_path)
        with open(version_json_path, 'r') as f:
            dict_data = json.load(f)
            dict_data['client'] = dict_data['downloads']['client']
            dict_data['server'] = dict_data['downloads']['server']
            del dict_data['downloads']

            lib_list = []
            for lib_info in dict_data['libraries']:
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
                    downinfo = lib_info['downloads']['classifiers'][lib_info['natives'][sys.platform]]
                else:
                    downinfo = lib_info['downloads']['artifact']

                allowed_lib['path'] = path.join(*downinfo['path'].split('/'))
                allowed_lib['url'] = downinfo['url']
                allowed_lib['sha1'] = downinfo['sha1']

                if "extract" in lib_info:
                    allowed_lib['extract'] = lib_info['extract']

                lib_list.append(allowed_lib)

            dict_data['libraries'] = lib_list
            self.version_config[version] = dict_data

    def fetch_version_all_file(self, version, download_server=False):
        '''下载指定版本的所有文件'''
        version_info = self.get_version_dict(version)

        client_file_path = path.join(self.get_version_path(version), version + '-cilent.jar')
        if not self.check_file(client_file_path, version_info['client']['sha1']):
            self.download_file(version_info['client']['url'], client_file_path)

        if download_server:
            server_file_path = path.join(self.get_version_path(version), version + '-server.jar')
            if not self.check_file(server_file_path, version_info['server']['sha1']):
                self.download_file(version_info['server']['url'], server_file_path)

        asset_index_path = path.join(self.assets_folder_path, 'indexes', version_info['assetIndex']['id'] + '.json')
        if not self.check_file(asset_index_path, version_info['assetIndex']['sha1']):
            self.download_file(version_info['assetIndex']['url'], asset_index_path)

            with open(asset_index_path, 'r') as f:
                for obj in json.load(f)['objects'].values():
                    hash_string = obj['hash']
                    obj_file_path = path.join(self.assets_folder_path, 'objects', hash_string[: 2], hash_string)
                    if not self.check_file(obj_file_path, hash_string):
                        self.download_file(
                            '{}/{}/{}'.format(self.api['objects_url'], hash_string[: 2], hash_string),
                            obj_file_path
                        )

        for allowed_lib in version_info['libraries']:
            file_path = path.join(self.libraries_folder_path, allowed_lib['path'])

            if self.check_file(file_path, allowed_lib['sha1']):
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


class PlayerNameError(Exception):
    pass


class EmailError(Exception):
    pass


class PasswordError(Exception):
    pass


class Launcher(object):

    def __init__(self, gamepath):
        self.gamepath = path.abspath(gamepath)
        self.user_config = ConfigManager(path.join(getcwd(), 'conf', 'userconf.json'))
        self.versions_manager = VersionManager(self.gamepath, MOJANG_API)
        self.authenticate_url = 'https://authserver.mojang.com/authenticate'
        self.refresh_url = 'https://authserver.mojang.com/refresh'

    def login_mojang(self, email=None, password=None):
        headers = {'Content-type': 'application/json'}

        if 'mojang' not in self.user_config:
            self.user_config['mojang'] = {}

        mojang_config = self.user_config['mojang']

        if 'clientToken' not in mojang_config:
            mojang_config['clientToken'] = uuid.uuid5(uuid.NAMESPACE_OID, 'mojang').hex

        if 'accessToken' not in mojang_config:
            if email is None:
                raise EmailError('Need Email Address!')
            if password is None:
                raise PasswordError('Need Password')

            res_data = requests.post(
                self.authenticate_url,
                headers=headers,
                data=json.dumps({
                    "agent": {"name": "Minecraft", "version": "1"},
                    "username": email,
                    "password": password,
                    "clientToken": mojang_config['clientToken']
                })
            ).json()

            if 'availableProfiles' not in res_data:
                raise LoginError('Login Failed:' + str(res_data))

            mojang_config['accessToken'] = res_data['accessToken']
            mojang_config['id'] = res_data['selectedProfile']['id']
            mojang_config['name'] = res_data['selectedProfile']['name']

        else:
            res_data = requests.post(
                self.refresh_url,
                headers=headers,
                data=json.dumps({
                    "accessToken": mojang_config['accessToken'],
                    "clientToken": mojang_config['clientToken']
                })
            ).json()

            if 'availableProfiles' not in res_data:
                raise LoginError('LogLegacy in Failed:' + str(res_data))

            mojang_config['id'] = res_data['selectedProfile']['id']
            mojang_config['name'] = res_data['selectedProfile']['name']

        self.user_config.save()
        return True

    def login_legacy(self, name=None):
        if 'legacy' not in self.user_config:
            self.user_config['legacy'] = {}

        legacy_config = self.user_config['legacy']

        if 'accessToken' not in legacy_config:
            legacy_config['accessToken'] = uuid.uuid5(uuid.NAMESPACE_OID, 'legacy').hex

        if 'id' not in legacy_config:
            legacy_config['id'] = legacy_config['accessToken']

        if name:
            legacy_config['name'] = name
        elif 'name' not in legacy_config:
            raise PlayerNameError('Need Player Name!')

        self.user_config.save()
        return True

    def run_game(self, version, java_path, user_type):
        version_dict = self.versions_manager.get_version_dict(version)

        cp_list = [path.join(self.versions_manager.libraries_folder_path, x['path']) for x in version_dict['libraries']]
        cp_list.append(path.join(self.versions_manager.get_version_path(version), version + '-cilent.jar'))

        cmd_str = '{java_path} -Djava.library.path={java_library_path} -cp {cpList} {mainClass} {minecraftArguments}'.format(
            java_path=java_path,
            java_library_path=path.join(self.versions_manager.get_version_path(version), 'natives'),
            cpList=':'.join(cp_list),
            mainClass=version_dict['mainClass'],
            minecraftArguments=version_dict['minecraftArguments'].format(
                auth_player_name=self.user_config[user_type]['name'],
                version_name=version,
                game_directory=self.gamepath,
                assets_root=self.versions_manager.assets_folder_path,
                assets_index_name=version_dict['assetIndex']['id'],
                auth_uuid=self.user_config[user_type]['id'],
                auth_access_token=self.user_config[user_type]['accessToken'],
                user_properties={},
                user_type=user_type,
                version_type=version_dict['type']
            ).replace('$', '')
        )
        child = subprocess.Popen(cmd_str, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while child.poll() is None:
            line = child.stdout.readline()
            print(line.decode())
