import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User, Bookmark } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signIn(dto: AuthDto) {
    // find the user by email
    // if the user not exist throw execption
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credentials incorrect');

    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    // if the password incorrect throw execption
    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');
    // return user
    delete user.hash;
    return this.signToken(user.id, user.email);
  }
  async signUp(dto: AuthDto) {
    // generate hash password
    const hash = await argon.hash(dto.password);

    try {
      // create new user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;
      // return saved user
      return this.signToken(user.id, user.email);
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw err;
    }
  }
  signToken(userId: number, email: string) {
    const payload = {
      sub: userId,
      email,
    };
    const token = this.jwt.sign(payload, {
      expiresIn: '15m',
      secret: this.config.get('secret_key'),
    });
    return {
      access_token: token,
    };
  }
}
