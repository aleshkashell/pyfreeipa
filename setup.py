from distutils.core import setup
setup(
  name = 'pyfreeipa',
  packages = ['pyfreeipa'], # this must be the same as the name above
  version = '0.1.4',
  description = 'Module for work with freeipa',
  author = 'Sheludchenkov Aleksey',
  author_email = 'aleshkashell@gmail.com',
  url = 'https://github.com/aleshkashell/pyfreeipa',
  download_url = 'https://github.com/aleshkashell/pyfreeipa/tarball/0.1.4',
  keywords = ['add', 'sub', 'tests', 'freeipa'], 
  classifiers = [],
  install_requires=[
          'requests',
          'kerberos',
          'dnspython',
      ],
)
