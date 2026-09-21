PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_clients` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`token_hash` text NOT NULL,
	`name` text NOT NULL,
	`environment_ids` text NOT NULL,
	`created_at` text NOT NULL,
	`expires_at` text,
	`last_seen` text,
	`revoked` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
INSERT INTO `__new_clients`("id", "tenant", "token_hash", "name", "environment_ids", "created_at", "expires_at", "last_seen", "revoked") SELECT "id", "tenant", "token_hash", "name", "environment_ids", "created_at", "expires_at", "last_seen", "revoked" FROM `clients`;--> statement-breakpoint
DROP TABLE `clients`;--> statement-breakpoint
ALTER TABLE `__new_clients` RENAME TO `clients`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `clients_token` ON `clients` (`token_hash`);--> statement-breakpoint
CREATE INDEX `clients_tenant` ON `clients` (`tenant`);