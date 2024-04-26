const mongoose = require('mongoose')

const connectToDatabase = async () => {
    await mongoose.connect(
        `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@nodejs.9vuq7zb.mongodb.net/database?retryWrites=true&w=majority&appName=Nodejs`)
        .then(console.log("Conexão efetuada com sucesso!"))
        .catch(error => {
            console.log('OCorreu um erro ao realizar a conexão: ', error)
        })
}

module.exports = connectToDatabase