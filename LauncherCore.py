import hashlib
import json
import sys
import zipfile
import subprocess
from os import getcwd, makedirs, path

import requests

MOJANG_API = {
    'version_manifest': 'https://launchermeta.mojang.com/mc/game/version_manifest.json',
    'objects_url': 'http://resources.download.minecraft.net',
}


def checkFileSHA1(filepath, sha1String):
    with open(filepath, 'rb') as f:
        sha1obj = hashlib.sha1()
        sha1obj.update(f.read())
        hashString = sha1obj.hexdigest()
        return hashString == sha1String


def downloadFile(url, filepath):
    http_res = requests.get(url)
    if not path.exists(path.dirname(filepath)):
        makedirs(path.dirname(filepath))
    with open(filepath, 'wb') as f:
        f.write(http_res.content)


class Launcher(object):

    def __init__(self, gamepath=None):

        self.gamepath = '.minecraft' if gamepath is None else gamepath
        if not path.isabs(self.gamepath):
            self.gamepath = path.join(getcwd(), self.gamepath)
        self.versionManifestPath = path.join(self.gamepath, 'version_manifest.json')
        self.versionsPath = path.join(self.gamepath, 'versions')
        self.assetsPath = path.join(self.gamepath, 'assets')
        self.assetsIndexesPath = path.join(self.assetsPath, 'indexes')
        self.librariesPath = path.join(self.gamepath, 'libraries')

    def getVersionBasePath(self, version):
        if version is None:
            raise ValueError('version is not given!')
        else:
            return path.join(self.versionsPath, version)

    def GetAllVersion(self):
        with open(self.versionManifestPath, 'r') as f:
            return json.load(f)['versions']
            # self.versions = {}
            # for ver in json.load(f)['versions']:
            # self.versions[ver['id']] = ver

    def readVersionInfoFromFile(self, version):
        version_base_path = self.getVersionBasePath(version)
        version_file_path = path.join(version_base_path, '%s.json' % (version))
        with open(version_file_path, 'r') as f:
            return json.load(f)

    def downloadVersionsManifest(self):
        downloadFile(MOJANG_API['version_manifest'], self.versionManifestPath)
        self.readAllVersions()

    def downloadVersionInfo(self, version):
        version_file_path = path.join(self.getVersionBasePath(version), '%s.json' % (version))
        downloadFile(self.versions[version]['url'], version_file_path)

    def downloadClient(self, version):
        down_info = self.readVersionInfoFromFile(version)['downloads']['client']
        file_path = path.join(self.getVersionBasePath(version), '%s-cilent.jar' % (version))
        if not (path.exists(file_path) and checkFileSHA1(file_path, down_info['sha1'])):
            downloadFile(down_info['url'], file_path)

    def downloadServer(self, version):
        down_info = self.readVersionInfoFromFile(version)['downloads']['server']
        file_path = path.join(self.getVersionBasePath(version), '%s-server.jar' % (version))
        if not (path.exists(file_path) and checkFileSHA1(file_path, down_info['sha1'])):
            downloadFile(down_info['url'], file_path)

    def downloadAssetFile(self, version):
        asset_index = self.readVersionInfoFromFile(version)['assetIndex']
        asset_index_path = path.join(self.assetsIndexesPath, '%s.json' % version)
        objects_base_path = path.join(self.assetsPath, 'objects')
        if not (path.exists(asset_index_path) and checkFileSHA1(asset_index_path, asset_index['sha1'])):
            downloadFile(asset_index['url'], asset_index_path)
        with open(asset_index_path, 'r') as f:
            objects = json.load(f)['objects']
            for obj in objects:
                print('download ', obj)
                hash_str = objects[obj]['hash']
                obj_file_path = path.join(objects_base_path, hash_str[:2], hash_str)
                if not (path.exists(obj_file_path) and checkFileSHA1(obj_file_path, hash_str)):
                    obj_url = '%s/%s/%s' % (MOJANG_API['objects_url'], hash_str[:2], hash_str)
                    downloadFile(obj_url, obj_file_path)

    def downloadLibFile(self, version):
        allow_lib_list = self.getAllowLibList(version)
        for lib in allow_lib_list:
            file_path = path.join(self.librariesPath, lib['path'])
            if not (path.exists(file_path) and checkFileSHA1(file_path, lib['sha1'])):
                print('download ', lib['name'])
                downloadFile(lib['url'], file_path)

            if "extract" in lib:
                exclude_list = lib['extract']['exclude']
                if zipfile.is_zipfile(file_path):
                    zipObj = zipfile.ZipFile(file_path)
                    filelist = zipObj.namelist()
                    for filepath in filelist.copy():
                        for exclude in exclude_list:
                            if filepath.find(exclude) == 0:
                                filelist.remove(filepath)
                    # print(filelist)
                    zipObj.extractall(members=filelist, path=path.join(self.getVersionBasePath(version), 'natives'))

    def isDisallowLibForRules(self, rules, platform=sys.platform):
        'check lib is disalow for rules!'
        result = True
        if rules is None:
            raise KeyError('rules is None')
        for rule in rules:
            if rule['action'] == 'allow' and ('os' in rule and rule['os']['name'] == platform):
                result = False
            elif rule['action'] == 'disallow' and rule['os']['name'] != platform:
                result = False

        return result

    def getAllowLibList(self, version):
        libs_info = self.readVersionInfoFromFile(version)['libraries']
        allow_lib_list = []
        for lib_info in libs_info:
            if 'rules' in lib_info and self.isDisallowLibForRules(lib_info['rules']):
                continue

            name = lib_info['name'].split(':')
            allow_lib = {'name': lib_info['name']}
            downinfo = lib_info['downloads']
            if 'natives' in lib_info:
                native = lib_info['natives'][sys.platform]
                allow_lib['path'] = path.join(*name[0].split('.'), *name[1:], '%s-%s-%s.jar' %
                                              (name[1], name[2], '-' + native))
                allow_lib['url'] = downinfo['classifiers'][native]['url']
                allow_lib['sha1'] = downinfo['classifiers'][native]['sha1']
            else:
                allow_lib['path'] = path.join(*name[0].split('.'), *name[1:], '%s-%s.jar' % (name[1], name[2]))
                allow_lib['url'] = downinfo['artifact']['url']
                allow_lib['sha1'] = downinfo['artifact']['sha1']

            if "extract" in lib_info:
                allow_lib['extract'] = lib_info['extract']

            allow_lib_list.append(allow_lib)
        return allow_lib_list

    def javaCMD(self, version, java_path, username):
        ver_info = self.readVersionInfoFromFile(version)
        cp_list = [path.join(self.librariesPath, x['path']) for x in self.getAllowLibList(version)]
        cp_list.append(path.join(self.getVersionBasePath(version), '%s-cilent.jar' % (version)))

        cmd = '{javaPath} -Djava.library.path={java_library_path} -cp {cp} {mainClass} {minecraftArguments}'.format(
            javaPath=java_path,
            java_library_path=path.join(self.getVersionBasePath(version), 'natives'),
            cp=':'.join(cp_list),
            mainClass=ver_info['mainClass'],
            minecraftArguments=ver_info['minecraftArguments'].format(
                auth_player_name=username,
                version_name=version,
                game_directory=self.gamepath,
                assets_root=self.assetsPath,
                assets_index_name=version,
                auth_uuid='cd6689cf93ce0be22258bef928b160ec',
                auth_access_token='cd6689cf93ce0be22258bef928b160ec',
                user_type='Legacy',
                version_type=ver_info['type']
            ).replace('$', '')
        )

        return cmd

    def RunGame(self, gameVersion, java_path, username):
        child = subprocess.Popen(l.javaCMD(version, java_path, username),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        while child.poll() is None:
            line = child.stdout.readline()
            sys.stdout.write(line.decode())
            sys.stdout.flush()

if __name__ == '__main__':
    version = '1.10'
    java_path = '/usr/lib/jvm/java-8-openjdk/jre/bin/java'
    username = 'test'
    l = Launcher()
    l.RunGame(version, java_path, username)
