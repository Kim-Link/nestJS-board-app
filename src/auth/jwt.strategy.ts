import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { InjectRepository } from "@nestjs/typeorm";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "./user.entity";
import { UserReopsitory } from "./user.repository";
import * as config from 'config';


@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        @InjectRepository(UserReopsitory)
        private userRepository: UserReopsitory
    ) {
        super({
            secretOrKey: process.env.SECRET || config.jwt.secret,
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
        })
    }

    async validate(payload) {
        const {username} = payload;
        const user: User = await this.userRepository.findOneBy({username});

        if(!user) {
            throw new UnauthorizedException();
        }

        return user;
    }
}