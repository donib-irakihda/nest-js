import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { error } from 'console';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      // Generate the hash
      const hash = await argon.hash(dto.password);

      // Save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      // return saved info
      return user;
    } catch (error) {
      if (
        error instanceof
        PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials taken',
          );
        }
      }
    }
    throw error;
  }

  async signin(dto: AuthDto) {
    // find the user by email
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    // if user not found, throw error
    if (!user) {
      throw new ForbiddenException(
        'Credentials incorrect',
      );
    }

    // compare password
    const pwMatch = await argon.verify(
      user.hash,
      dto.password,
    );

    // if password is incorrect, throw error
    if (!pwMatch)
      throw new ForbiddenException(
        'Credentials incorrect',
      );

    // send back the user
    delete user.hash;
    return user;
  }
}
