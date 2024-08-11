import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import connectDB from "@/db";
import routes from "@routes";
import express from "express";
import { errors } from "celebrate";
import rateLimit from "express-rate-limit";
import errorHandler from "@middleware/errorHandler";

dotenv.config();

(async function () {
    await connectDB();

    const app = express();

    app.use(cors());

    app.use(helmet());
    app.use(express.json());
    app.use(routes);

    /* Global error handler for Celebrate validation errors */
    app.use(errors());

    /* Error handling middleware */
    app.use(errorHandler);

    /* Rate Limiting */
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
    });

    app.use(limiter);

    app.listen(process.env["PORT"] as string, () => {
        console.debug(`Server is running on http://localhost:${process.env["PORT"]}`);
    });
}());
