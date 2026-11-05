# SPDX-License-Identifier: MIT
include $(TOPDIR)/rules.mk

PKG_NAME:=be6l-recovery-guard
PKG_VERSION:=1.0.0
PKG_RELEASE:=2
PKG_LICENSE:=MIT
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/be6l-recovery-guard
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=BE6L Pro initramfs SSH heartbeat recovery
  DEPENDS:=@TARGET_ROOTFS_INITRAMFS +busybox +procd +uci +dropbear
endef

define Package/be6l-recovery-guard/description
  Reboot a BE6L Pro RAM system after authenticated SSH heartbeats expire.
  This does not open or take ownership of the hardware watchdog.
endef

define Package/be6l-recovery-guard/conffiles
/etc/config/be6l-recovery
endef

define Build/Compile
endef

define Package/be6l-recovery-guard/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/usr/sbin $(1)/usr/lib/be6l-recovery-guard
	$(INSTALL_CONF) ./files/be6l-recovery.config $(1)/etc/config/be6l-recovery
	$(INSTALL_BIN) ./files/be6l-recovery.init $(1)/etc/init.d/be6l-recovery
	$(INSTALL_BIN) ./files/be6l-recovery-guard $(1)/usr/sbin/be6l-recovery-guard
	$(INSTALL_DATA) ./files/state.sh $(1)/usr/lib/be6l-recovery-guard/state.sh
endef

$(eval $(call BuildPackage,be6l-recovery-guard))
