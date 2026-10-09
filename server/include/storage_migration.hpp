#pragma once

// 新版数据迁移入口：对 SQLite 库执行角色模型迁移。

struct sqlite3;

namespace richnet::storage_detail {
void migrate_richonline_models(sqlite3* database);
}
