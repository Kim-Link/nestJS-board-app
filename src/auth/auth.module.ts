import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from './user.entity';
import { UserReopsitory } from './user.repository';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import * as config from 'config'

const jwtConfig = config.get('jwt')

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt'}),
    JwtModule.register({
    secret: process.env.JWT_SECRET || jwtConfig.secret,
    signOptions:{
      expiresIn: jwtConfig.expiresIn,
    }
  }),TypeOrmModule.forFeature([User])],
  controllers: [AuthController],
  providers: [AuthService, UserReopsitory, JwtStrategy],
  exports: [JwtStrategy, PassportModule]
})
export class AuthModule {}
