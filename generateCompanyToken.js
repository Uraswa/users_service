import dotenv from "dotenv"

dotenv.config();

import CompanyModel from "./companyModel.js";

console.log(await CompanyModel.createCompany());