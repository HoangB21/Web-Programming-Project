"use strict";
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable("mediafiles", {
      file_id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        allowNull: false,
        primaryKey: true,
      },
      post_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: "posts",
          key: "post_id"
        }
      },
      file_content: {
        type: Sequelize.BLOB('long'),
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
    await queryInterface.dropTable("mediafiles");
  },
};
