/* register_types.cpp */

#include "register_types.h"

#include "core/object/class_db.h"
#include "tcp_ext.h"

void initialize_tcpext_module(ModuleInitializationLevel p_level) {

    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
            return;
    }

    ClassDB::register_class<TCPExt>();
}

void uninitialize_tcpext_module(ModuleInitializationLevel p_level) {
    if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
            return;
    }
}
