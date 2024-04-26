const express = require("express")
const User = require('../src/models/user.model')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

app.use(express.json())

//Rota pública
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem-Vindo!' })
})

//Rota privada para busca de usuários pelo ID com validação de token
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }
    
    res.status(200).json({ user })
})

//Função para verificar o TOKEN
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: 'Não autorizado!' })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        return res.status(400).json({ msg: 'Token Inválido!' })
    }
}

//Registro de usuário
app.post('/auth/register', async (req, res) => {
    const { username, email, password} = req.body

    //verifica se os campos foi preenchido corretamente
    if(!username){
        return res.status(422).json({ msg: 'Nome de usuário é obrigatório!' })
    }

    if(!email){
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }

    if(!password){
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    function getCharacterLength(password) {
        return [...password].length;
      }
      
    if(getCharacterLength(password) < 8){
        return res.status(422).json({ msg: 'A senha deve ter pelo menos 8 caracteres!' })
    }

    if(!password.match(/[a-z]+/)){
        return res.status(422).json({ msg: 'A senha deve conter pelo menos 1 letra minúscula!' })
    }

    if(!password.match(/[A-Z]+/)){
        return res.status(422).json({ msg: 'A senha deve conter pelo menos 1 letra maiúscula!' })
    }

    if(!password.match(/[0-9]+/)){
        return res.status(422).json({ msg: 'A senha deve conter pelo menos 1 número!' })
    }

    if(!password.match(/[!@#$%^&*(),.?\":{}|<>]+/)){
        return res.status(422).json({ msg: 'A senha deve conter pelo menos 1 caractere especial!' })
    }
    
    const userExists = await User.findOne({ username: username })

    //verifica se não existe usuário ou email cadastrado
    if (userExists) {
        return res.status(422).json("Nome de usuário ja está em uso!")
    }

    const emailExists = await User.findOne({ email: email })

    if (emailExists) {
        return res.status(422).json({ msg: 'Email já está em uso!' })
    }

    //criacao de HASH para a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        username,
        email,
        password: passwordHash,
    })

    try {
        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso!'})
    } catch (error) {
        console.log(error)

        res.status(500).json({msg: 'Erro no servidor, tente novamente!'})
    }
})


//login do usuário
app.post("/auth/login", async (req, res) => {
    const {email, password} = req.body

    if(!email){
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }

    if(!password){
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    const mail = await User.findOne({ email: email })

    if (!mail) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    //verifica se a senha está correta
    const validPassword = await bcrypt.compare(password, mail.password)

    if (!validPassword) {
        return res.status(422).json({ msg: 'Senha incorreta!' })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({ id: mail._id }, secret, { expiresIn: 300 })

        res.status(200).json({ msg: 'Autenticação realizada com sucesso!', token})
    } catch (error) {
        console.log(error)

        res.status(500).json({msg: 'Erro, tente novamente!'})
    }
})

//Atualizar informações do usuário pelo ID (Update)
app.patch('/user/:id', async (req, res) => {
    try {
        const id = req.params.id
        const user = await User.findByIdAndUpdate(id, req.body, {new: true})

        res.status(200).json(user)
    } catch (error) {
        res.status(500).send({msg: 'Erro, verifique o ID e tente novamente!'})
    }
})

//Excluir registro de usuário através do ID (Delete)
app.delete('/user/:id', async (req, res) => {
    try {
        const id = req.params.id

        const user = await User.findByIdAndDelete(id)

        res.status(200).json(user)
    } catch (error) {
        res.status(500).send({msg: 'Erro, verifique o ID e tente novamente!'})
    }
})

const port = 8080

app.listen(port, () => console.log(`Rodando na porta ${port}`))