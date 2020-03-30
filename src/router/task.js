const express = require('express')
const router = express.Router()
const Task = require('../models/task')

router.get('/tasks',async (req,res) => {

    try{
        const users = await Task.findOne({})
        res.send(users)
    }
    catch(e) {
        res.status(500).send()
    }
})

router.get('/tasks/:id',async (req, res) => {

     const _id = req.params.id
    try{
        const task = await Task.findById({_id})
        if(!task){
            res.status(404).send()
        }
        res.send(task)
    }
    catch(e) {
        res.status(500).send()
    }
})



router.post('/tasks',async (req,res) => {
    const task = new Task(req.body)

     try{
        await task.save()
        res.status(201).send(task)
    }
    catch (e){
        res.status(400).send(e)
    }
})


router.patch('/tasks/:id',async (req, res) => {
    const updates = Object.keys(req.body)
    const allowedUpdates = ['description', 'completed']
    isVallidOperation = updates.every((update) => allowedUpdates.includes(update))

    if(!isVallidOperation){
        return res.status(400).send({error: 'Invalid Upadates!'} )
    }
    
    try{
        const task = await Task.findById(req.params.id)
        updates.forEach((update) => task[update] = req.body[update])
        await task.save()
    
        if(!task){
            res.status(404).send()
        }
        res.send(task)
    }
    catch(e){
        res.status(400).send(e)
    }
    

})

router.delete('/tasks/:id',async (req,res) =>{
    try{
        const task = await Task.findByIdAndDelete(req.params.id)

        if(!task){
            res.status(404).send()
        }
        res.send(task)
    }
    catch(e){
        res.status(500).send()
    }
})

module.exports = router