# Геоданные и уведомления

© [OpenStreetMap contributors](https://www.openstreetmap.org/copyright).
Производные географические базы T-Maps доступны под
[Open Data Commons Open Database License 1.0](https://opendatacommons.org/licenses/odbl/1-0/).
Эта лицензия относится к данным, отдельно от приложения и библиотек.

Полные производные базы включены в IPA без шифрования или DRM, доступны бесплатно
из того же GitHub Release и могут быть извлечены и повторно использованы на условиях ODbL.
Текущий региональный источник — OSM France Central Federal District,
снимок 2026-11-03T00:08:06Z; описание источника, границы и SHA-256 содержатся в манифестах.
Обновляемый upstream: https://download.openstreetmap.fr/extracts/russia/central_federal_district.osm.pbf
Этот URL не считается неизменяемой копией исторического снимка.

## Полная копия производных баз

Скачать `T-Maps-0.9.2-rc-20-public.ipa` из Assets сборки, проверить SHA-256 по `SHA256SUMS.txt`.
На macOS можно извлечь данные в новую пустую папку:

```sh
mkdir osm-data
unzip -j T-Maps-0.9.2-rc-20-public.ipa 'Payload/CityAtlas.app/moscow-*' -d osm-data
compression_tool -decode -a lzfse -i osm-data/moscow-places.sqlite.lzfse -o osm-data/moscow-places.sqlite
compression_tool -decode -a lzfse -i osm-data/moscow-routing.tar.lzfse -o osm-data/moscow-routing.tar
compression_tool -decode -a lzfse -i osm-data/moscow-transit-topology.json.lzfse -o osm-data/moscow-transit-topology.json
shasum -a 256 osm-data/moscow-places.sqlite osm-data/moscow-routing.tar osm-data/moscow-transit-topology.json
```

LZFSE — обычный открытый формат; для других систем доступен
[официальный декодер lzfse](https://github.com/lzfse/lzfse).

| База | Распакованный размер, байт | SHA-256 |
| --- | ---: | --- |
| Поиск, SQLite | 672116736 | `a5af43a1e2921ed860b7a5aa722429d53c32db7e0c7be78f611e8c0595fd5329` |
| Дорожный граф Valhalla, TAR | 522158080 | `30fc63f16107711f5c11d478fa959cd90c5774b7b635a3072e530aa80aa10a8c` |
| Транспортная топология, JSON | 75002234 | `8280301623cd2ba9c5625d3c6aaf683807561475496da27183f826c4b9b9756a` |

Остальные `moscow-*` JSON/GeoJSON/TMGraph в IPA — открытая транспортная геометрия,
входы, метаданные и вспомогательный пешеходный граф того же ODbL-происхождения.
Текущие региональные данные и сохранённый legacy auxiliary walking graph имеют отдельные
идентификаторы в `moscow-region-cohort.json`; они не выдаются за один снимок.
Упаковка не меняет геометрию, записи, исходные идентификаторы или SHA-256 самих баз.

## Библиотеки

В IPA сохранены LICENSE / ThirdParty notices MapLibre, Valhalla, llama.cpp, LlamaSwift,
Noto Sans и остальных включённых зависимостей. Их лицензии действуют отдельно.
Публичные GitHub Actions runner paths внутри неизменённых библиотек Valhalla/llama.cpp
относятся к upstream сборкам. Локальные пути владельца в публичной упаковке удалены.
