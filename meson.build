libjwt = dependency('libjwt')
libcurl = dependency('libcurl')

add_languages('cpp')

args_update = {
'dependencies': contrib_mod_args.get('dependencies') + [libcurl, libjwt],
'cpp_args': contrib_mod_args.get('cpp_args') + ['-std=c++23'],
}
mod_args = contrib_mod_args + args_update

pg_oauth_sources = files(
  'src/pg_oauth.cpp',
  'src/http_client.cpp',
  'src/jwk.cpp',
)

pg_oauth = shared_module('pg_oauth',
  pg_oauth_sources,
  kwargs: mod_args,
  include_directories: ['jwt-cpp/include/'],
)
contrib_targets += pg_oauth

