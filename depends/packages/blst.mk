package=blst
$(package)_version=0.3.11
$(package)_download_path=https://github.com/supranational/blst/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=d0a6e2a69490cc45f0a531a684a225e56fe22303665157cfa397ba5605447eb9
$(package)_dependencies=

define $(package)_set_vars
  $(package)_config_opts=CC="$($(package)_cc)"
  $(package)_config_opts+=AR="$($(package)_ar)"
endef

define $(package)_config_cmds
  true
endef

define $(package)_build_cmds
  ./build.sh
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/include/blst && \
  mkdir -p $($(package)_staging_dir)$(host_prefix)/lib && \
  cp bindings/blst.h $($(package)_staging_dir)$(host_prefix)/include/blst/ && \
  cp bindings/blst_aux.h $($(package)_staging_dir)$(host_prefix)/include/blst/ && \
  cp libblst.a $($(package)_staging_dir)$(host_prefix)/lib/ && \
  if test -f bindings/blst.hpp; then cp bindings/blst.hpp $($(package)_staging_dir)$(host_prefix)/include/blst/; fi
endef