import os

from setuptools import setup, find_packages

def find_data_files(data_dir):
    content = []
    for root, dirs, files in os.walk(data_dir):
        content.append(os.path.relpath(root, data_dir), [os.path.join(root, f) for f in files])
    return content

# data_files = find_data_files['etc']

setup(
    name='cherrywasp',
    version='2.2',
    packages=find_packages(where='src', exclude='test'),
    package_dir={"": "src"},
    # data_files=data_files,
    url='https://github.com/ajackal/cherry-wasp.git',
    license='',
    author='cmiller',
    author_email='ajackal244@gmail.com',
    description='802.11 beacon and probe request scanner.',
    install_requires=['scapy', 'termcolor', 'pytest']
)
