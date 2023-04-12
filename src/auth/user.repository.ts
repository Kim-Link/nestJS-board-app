import { ConflictException, InternalServerErrorException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { DataSource, Repository } from "typeorm";
import { AuthCredentialsDto } from "./dto/auth-credential.dto";
import { User } from "./user.entity";
import * as bcrypt from 'bcryptjs'

export class UserReopsitory extends Repository<User> {
    constructor(@InjectRepository(User) private dataSource: DataSource) {
        super(User, dataSource.manager) // 변경
        
    }
    async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        const { username, password } = authCredentialsDto;
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const user = this.create({username, password: hashedPassword });

        try {
            await this.save(user);
        } catch (error) {
            if(error.code === '23505') {
                throw new ConflictException('Existing username');
            } else {
                throw new InternalServerErrorException();
            }
        }
    }
}
