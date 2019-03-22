from setuptools import setup

setup(
    name='cherrywasp',
    version='2.0',
    packages=['cherrywasp'],
    url='https://github.com/ajackal/cherry-wasp.git',
    license='',
    author='cmiller',
    author_email='ajackal244@gmail.com',
    description='802.11 beacon and probe request scanner.',
    install_requires=['scapy', 'termcolor', 'pytest']
)
