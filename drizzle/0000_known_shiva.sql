CREATE TABLE `clients` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`token_hash` text NOT NULL,
	`name` text NOT NULL,
	`environment_ids` text NOT NULL,
	`created_at` text NOT NULL,
	`expires_at` text NOT NULL,
	`last_seen` text,
	`revoked` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `clients_token` ON `clients` (`token_hash`);--> statement-breakpoint
CREATE INDEX `clients_tenant` ON `clients` (`tenant`);--> statement-breakpoint
CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`time` text NOT NULL,
	`kind` text NOT NULL,
	`body` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `events_tenant_time` ON `events` (`tenant`,`time`);--> statement-breakpoint
CREATE TABLE `releases` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`sequence` integer NOT NULL,
	`body` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `releases_tenant_sequence` ON `releases` (`tenant`,`sequence`);--> statement-breakpoint
CREATE TABLE `revisions` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`policy_id` text NOT NULL,
	`body` text NOT NULL,
	`time` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `revisions_tenant_policy` ON `revisions` (`tenant`,`policy_id`);--> statement-breakpoint
CREATE TABLE `workspaces` (
	`id` text PRIMARY KEY NOT NULL,
	`snapshot` text NOT NULL,
	`revision` integer DEFAULT 1 NOT NULL,
	`sequence` integer DEFAULT 0 NOT NULL,
	`mutation` text NOT NULL,
	`public_key` text NOT NULL,
	`private_key` text NOT NULL
);
