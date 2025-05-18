import bcrypt from "bcrypt";
import pg from 'pg'
import jwt from "jsonwebtoken";

const {Pool} = pg;

// Конфигурация соединений
const dbConfig = {
    master: {
        user: 'postgres',
        host: 'localhost', // или IP мастера
        database: 'postgres',
        password: 'nice',
        port: 6500,
    },
    slaves: [
        {
            user: 'postgres',
            host: 'localhost', // или IP первого slave
            database: 'postgres',
            password: 'nice',
            port: 6501,
        },
        {
            user: 'postgres',
            host: 'localhost', // или IP второго slave
            database: 'postgres',
            password: 'nice',
            port: 6502,
        }
    ]
};


const masterPool = new Pool(dbConfig.master);
const slavePools = dbConfig.slaves.map(config => new Pool(config));


let currentSlaveIndex = 0;

function getSlavePool() {
    const pool = slavePools[currentSlaveIndex];
    currentSlaveIndex = (currentSlaveIndex + 1) % slavePools.length;
    return pool;
}


async function db_query(sql, values = [], isWriteQuery = false) {
    const pool = isWriteQuery ? masterPool : getSlavePool();

    return await pool.query(sql, values);

}

class CompanyModel {


    async createCompany() {
        let client = await masterPool.connect();
        let res = "";
        try {
            client.query('BEGIN');

            let q1 = await masterPool.query(`INSERT INTO companies DEFAULT
                                             VALUES RETURNING *`);
            let company = q1.rows[0];
            let q2 = await masterPool.query(`INSERT INTO users (is_activated, company_id) VALUES (true, $1) RETURNING *`, [company.company_id]);

            let user = q2.rows[0]

            let payload = {
                is_company: true,
                company_id: company.company_id,
                user_id: user.user_id,
                iat: Math.floor(Date.now() / 1000)
            }

            res = jwt.sign(payload, process.env.JWT_ACCESS_SECRET);
            client.query('COMMIT');
        } catch (e) {
            client.query('ROLLBACK');
        } finally {
            client.release();
        }

        return res;


    }

    async doesCompanyExist(company_id){
        const query = `SELECT *
                       FROM companies
                       WHERE company_id = $1`;
        const result = await db_query(query, [company_id]);
        return result.rows[0];
    }
}

export default new CompanyModel();