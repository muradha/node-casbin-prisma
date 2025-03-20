-- CreateTable
CREATE TABLE `User` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(191) NOT NULL,
    `role` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `User_username_key`(`username`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `CasbinRule` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `ptype` VARCHAR(191) NOT NULL,
    `v0` VARCHAR(191) NULL,
    `v1` VARCHAR(191) NULL,
    `v2` VARCHAR(191) NULL,
    `v3` VARCHAR(191) NULL,
    `v4` VARCHAR(191) NULL,
    `v5` VARCHAR(191) NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
