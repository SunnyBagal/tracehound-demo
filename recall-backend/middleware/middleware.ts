import jwt, { type JwtPayload } from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

const JWT_SECRET = process.env.JWT_SECRET!;

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ msg: "No token provided" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET) as JwtPayload;
    if (typeof payload === "object" && payload.userId) {
      req.userId = payload.userId;
      return next();
    }
    return res.status(401).json({ msg: "Unauthorized" });
  } catch {
    return res.status(401).json({ msg: "Invalid token" });
  }
};
