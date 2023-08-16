module.exports = (sequelize, Sequelize) => {
    const Role = sequelize.define("users", {
      role: {
        type: Sequelize.STRING
      }
    });
  
    return Role;
  };