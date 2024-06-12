"use strict";
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable("comments", {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
      owner: {
        type: Sequelize.STRING,
        references: {
          model: "users",
          key: "user_id",
        },
      },
      post_id: {
        type: Sequelize.UUID,
        references: {
          model: "posts",
          key: "post_id",
        },
      },
      content: {
        type: Sequelize.TEXT,
      },
      replyTo: {
        type: Sequelize.STRING,
      },
      createdAt: {
        type: Sequelize.DATE,
      },
      updatedAt: {
        type: Sequelize.DATE,
      },
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable("comments");
  },
};
