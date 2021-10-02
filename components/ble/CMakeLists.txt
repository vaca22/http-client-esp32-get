set(srcs "gatt_svr.c")

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS  "."
                    REQUIRES console nvs_flash bt
                    REQUIRED_IDF_TARGETS esp32)
