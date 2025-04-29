import pg from "pg";

const {Pool} = pg;
class Model {

    static globalPool;
    pool;
    constructor() {
        this.pool = Model.globalPool;
    }

    static connect(){
        Model.globalPool = new Pool({
            user: 'nice',
            host: 'localhost',
            database: 'users',
            password: 'nice',
            port: 5432,
        })
    }

}

Model.connect();
export default Model;