"use strict";
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable("posts", {
      post_id: {
        type: Sequelize.UUID,
        allowNull: false,
        primaryKey: true,
      },
      author: {
        type: Sequelize.STRING,
        allowNull: false,
        references: {
          model: "users",
          key: "user_id",
        },
        onUpdate: "CASCADE",
        onDelete: "CASCADE",
      },
      content: {
        type: Sequelize.TEXT,
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
      },
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable("posts");
  },
};
