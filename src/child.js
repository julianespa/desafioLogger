const randoms = (cant) => {
    let obj = {}
    if(!isNaN(cant)){
        for(let i = 0;i<cant;i++){
            let num = Math.floor(Math.random()*1000)+1
            if(obj[num]){
                obj[num] += 1
            } else {
                obj[num]=1
            }
        }
    }
    return obj
}


process.on('message',cant=>{
   let result = randoms(cant)
   process.send(result)
})

