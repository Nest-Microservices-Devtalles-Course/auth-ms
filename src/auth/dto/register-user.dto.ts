import {IsEmail, IsString, IsStrongPassword} from "class-validator";

export class RegisterUserDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsString()
  @IsStrongPassword()
  password: string;
}