from setuptools import setup, find_packages
import os

version = '0.1.0'

setup(name='buckler',
      version=version,
      description="Proxy for ES",
      long_description=open("README.md").read(),
      classifiers=[
        "Programming Language :: Python",
        ],
      keywords='',
      author='Ivo van der Wijk',
      author_email='banana@in.m3r.nl',
      url='http://m3r.nl/',
      license='BSD',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=[],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'requests',
      ],
      entry_points={
      },

      )
