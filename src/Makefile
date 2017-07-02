# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=c3h-client
PKG_RELEASE:=1
PKG_VERSION:=1.0.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/c3h-client
	SECTION:=net
	CATEGORY:=Network
	TITLE:=FOSU 802.1X client by KiritoA
	DEPENDS:=+libpcap
endef

define Package/c3h-client/description
	Support FOSU private authentication protocol.
	Thanks to njit8021xclient make by liuqun.
endef

define Build/Prepare
	echo "Here is Package/Prepare"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/c3h-client/install
	echo "Here is Package/install"
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/c3h-client $(1)/bin/
endef

$(eval $(call BuildPackage,c3h-client))
