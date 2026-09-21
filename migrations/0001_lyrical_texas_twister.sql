CREATE TABLE `policy_history` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`policy_id` text NOT NULL,
	`version` integer NOT NULL,
	`body` text NOT NULL,
	`superseded_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `policy_history_version` ON `policy_history` (`tenant`,`policy_id`,`version`);--> statement-breakpoint
ALTER TABLE `events` ADD `environment_id` text;--> statement-breakpoint
CREATE INDEX `events_environment_time` ON `events` (`tenant`,`environment_id`,`kind`,`time`);--> statement-breakpoint
ALTER TABLE `workspaces` ADD `model_version` integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE `workspaces` ADD `updated_at` text DEFAULT '1970-01-01T00:00:00.000Z' NOT NULL;