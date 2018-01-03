#!/bin/bash

#https://developer.gnome.org/gio/stable/gdbus-codegen.html


WPA_SUPP_MAIN_OBJ="fi.w1.wpa_supplicant1"
WPA_SUPP_XML="wpa_supplicant.xml"
WPA_SUPP_INTERFACE_XML="wpa_supplicant_interface.xml"
WPA_SUPP_INTERFACE_WPS_XML="wpa_supplicant_interface_wps.xml"
WPA_SUPP_INTERFACE_P2PDEV="wpa_supplicant_interface_p2pdev.xml"
WPA_SUPP_PEER_XML="wpa_supplicant_peer.xml"
WPA_SUPP_GROUP_XML="wpa_supplicant_group.xml"
WPA_SUPP_PERSISTENT_GROUP_XML="wpa_supplicant_persistent_group.xml"

#sudo gdbus introspect -y -d ${WPA_SUPP_MAIN_OBJ} -o /fi/w1/wpa_supplicant1 --xml > ${WPA_SUPP_XML}
#gdbus-codegen --interface-prefix fi.w1.wpa_supplicant1.  \
#	      --generate-c-code wpa --c-namespace wpa \
#	      --annotate "fi.w1.wpa_supplicant1:WFDIEs" org.gtk.GDBus.C.ForceGVariant true \
 #	      ${WPA_SUPP_XML}

#sudo gdbus introspect -y -d "${WPA_SUPP_MAIN_OBJ}" -o /fi/w1/wpa_supplicant1/Interfaces/5 --xml > ${WPA_SUPP_INTERFACE_XML}
#gdbus-codegen --interface-prefix fi.w1.wpa_supplicant1.Interface.  \
#	      --generate-c-code wpa_interface --c-namespace wpa_interface \
# 	      ${WPA_SUPP_INTERFACE_XML}

#sudo gdbus introspect -y -d "${WPA_SUPP_MAIN_OBJ}" -o /fi/w1/wpa_supplicant1/Interfaces/11/Peers/76a52867c92e --xml > ${WPA_SUPP_PEER_XML}
#gdbus-codegen --interface-prefix fi.w1.wpa_supplicant1.Peer. \
#	      --generate-c-code wpa_peer --c-namespace wpa_peer \
#	      ${WPA_SUPP_PEER_XML}


sudo gdbus introspect -y -d "${WPA_SUPP_MAIN_OBJ}" -o /fi/w1/wpa_supplicant1/Interfaces/3/Groups/4K --xml > ${WPA_SUPP_GROUP_XML}
gdbus-codegen --interface-prefix fi.w1.wpa_supplicant1.Group. \
	      --generate-c-code wpa_group --c-namespace wpa_group \
 	      ${WPA_SUPP_GROUP_XML}
