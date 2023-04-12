import { Body, Controller, Get, Param, Post, Delete, Patch, UsePipes, ValidationPipe, ParseIntPipe, UseGuards, Logger } from '@nestjs/common';
import { BoardsService } from './boards.service';
import { BoardStatus } from './board-status.enum';
import { CreateBoardDto } from './dto/create-board.dto';
import { BoardStatusValidationPipe } from './pipes/board-status-validation.pipe';
import { Board } from './board.entity';
import { AuthGuard } from '@nestjs/passport';
import { GetUser } from 'src/auth/get-user.decorator';
import { User } from 'src/auth/user.entity';

@Controller('boards')
@UseGuards(AuthGuard())
export class BoardsController {
  private logger = new Logger('Board');
  constructor(private boardService: BoardsService) {}


  @Get()
  getAllBoard(
    @GetUser() user:User
  ): Promise<Board[]> {
    this.logger.verbose(`User ${user.username} trying to get all boards`);
    return this.boardService.getAllBoards(user);
  }

  // @Get('/')
  // getAllBoard(): Board[] {
  //   return this.boardService.getAllBoards();
  // }

  // @Post()
  // @UsePipes(ValidationPipe)
  // createBoard(@Body() createBoardDto: CreateBoardDto): Board {
  //   return this.boardService.createBoard(createBoardDto);
  // }

  @Post()
  @UsePipes(ValidationPipe)
  craeteBoard(@Body() createBoardDto: CreateBoardDto,
  @GetUser() user:User): Promise<Board> {
    this.logger.verbose(`User ${user.username} creating a new board. 
    Payload: ${JSON.stringify(createBoardDto)}`)
    return this.boardService.createBoard(createBoardDto, user);
  }

  @Get('/:id')
  getBoardById(@Param('id') id:number) : Promise<Board> {
    return this.boardService.getBoardById(id);
  }

  // @Get('/:id')
  // getBoardById(@Param('id') id: string): Board {
  //   return this.boardService.getBoardById(id);
  // }

  @Delete('/:id')
  deleteBoard(@Param('id', ParseIntPipe) id,
  @GetUser() user: User): Promise<void> {
    return this.boardService.deleteBoard(id, user);
  }
  // @Delete('/:id')
  // deleteBoard(@Param('id') id: string): void {
  //   this.boardService.deleteBoard(id);
  // }

  @Patch('/:id/status')
  updateBoardStatus(
    @Param('id', ParseIntPipe) id: number,
    @Body('status', BoardStatusValidationPipe ) status: BoardStatus,
  ){
    return this.boardService.updateBoardStatus(id, status);
  }

  // @Patch('/:id/status')
  // updateBoardStatus(
  //   @Param('id') id: string,
  //   @Body('status', BoardStatusValidationPipe ) status: BoardStatus,
  // ){
  //   return this.boardService.updateBoardStatus(id, status);
  // }


}
