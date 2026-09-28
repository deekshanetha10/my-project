import React, { useState, useEffect, useRef, useCallback } from 'react';

const GRID_SIZE = 20;
const INITIAL_SNAKE = [{ x: 10, y: 10 }, { x: 10, y: 11 }, { x: 10, y: 12 }];
const INITIAL_DIRECTION = { x: 0, y: -1 };
const INITIAL_SPEED = 100;

type Point = { x: number; y: number };

const TRACKS = [
  { id: 1, title: "DATA_STREAM_01.WAV", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3" },
  { id: 2, title: "VOID_RESONANCE.MP3", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-2.mp3" },
  { id: 3, title: "SYNTHETIC_DECAY.OGG", url: "https://www.soundhelix.com/examples/mp3/SoundHelix-Song-3.mp3" },
];

export default function App() {
  // Game State
  const [hasStarted, setHasStarted] = useState(false);
  const [snake, setSnake] = useState<Point[]>(INITIAL_SNAKE);
  const [food, setFood] = useState<Point>({ x: 15, y: 5 });
  const [score, setScore] = useState(0);
  const [gameOver, setGameOver] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  
  // Refs for game loop to avoid dependency issues
  const directionRef = useRef<Point>(INITIAL_DIRECTION);
  const lastProcessedDirRef = useRef<Point>(INITIAL_DIRECTION);

  // Music State
  const [currentTrackIdx, setCurrentTrackIdx] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const audioRef = useRef<HTMLAudioElement>(null);

  const generateFood = useCallback((currentSnake: Point[]) => {
    let newFood: Point;
    while (true) {
      newFood = {
        x: Math.floor(Math.random() * GRID_SIZE),
        y: Math.floor(Math.random() * GRID_SIZE)
      };
      // eslint-disable-next-line no-loop-func
      if (!currentSnake.some(segment => segment.x === newFood.x && segment.y === newFood.y)) {
        break;
      }
    }
    return newFood;
  }, []);

  const startGame = () => {
    setHasStarted(true);
    if (!isPlaying) setIsPlaying(true);
  };

  const resetGame = () => {
    setSnake(INITIAL_SNAKE);
    directionRef.current = INITIAL_DIRECTION;
    lastProcessedDirRef.current = INITIAL_DIRECTION;
    setScore(0);
    setGameOver(false);
    setFood(generateFood(INITIAL_SNAKE));
    setIsPaused(false);
  };

  // Keyboard Controls
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', ' '].includes(e.key)) {
        e.preventDefault();
      }
      
      if (!hasStarted || gameOver) return;

      if (e.key === ' ') {
        setIsPaused(p => !p);
        return;
      }

      const lastDir = lastProcessedDirRef.current;
      
      switch (e.key) {
        case 'ArrowUp':
        case 'w':
        case 'W':
          if (lastDir.y !== 1) directionRef.current = { x: 0, y: -1 };
          break;
        case 'ArrowDown':
        case 's':
        case 'S':
          if (lastDir.y !== -1) directionRef.current = { x: 0, y: 1 };
          break;
        case 'ArrowLeft':
        case 'a':
        case 'A':
          if (lastDir.x !== 1) directionRef.current = { x: -1, y: 0 };
          break;
        case 'ArrowRight':
        case 'd':
        case 'D':
          if (lastDir.x !== -1) directionRef.current = { x: 1, y: 0 };
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown, { passive: false });
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [hasStarted, gameOver]);

  // Game Loop
  useEffect(() => {
    if (!hasStarted || gameOver || isPaused) return;

    const moveSnake = () => {
      setSnake(prevSnake => {
        const head = prevSnake[0];
        const currentDir = directionRef.current;
        lastProcessedDirRef.current = currentDir;
        
        const newHead = {
          x: head.x + currentDir.x,
          y: head.y + currentDir.y
        };

        // Wall Collision
        if (newHead.x < 0 || newHead.x >= GRID_SIZE || newHead.y < 0 || newHead.y >= GRID_SIZE) {
          setGameOver(true);
          return prevSnake;
        }

        // Self Collision
        if (prevSnake.some(segment => segment.x === newHead.x && segment.y === newHead.y)) {
          setGameOver(true);
          return prevSnake;
        }

        const newSnake = [newHead, ...prevSnake];

        // Food Collision
        if (newHead.x === food.x && newHead.y === food.y) {
          setScore(s => s + 1);
          setFood(generateFood(newSnake));
        } else {
          newSnake.pop();
        }

        return newSnake;
      });
    };

    const intervalId = setInterval(moveSnake, INITIAL_SPEED);
    return () => clearInterval(intervalId);
  }, [hasStarted, gameOver, isPaused, food, generateFood]);

  // Music Controls
  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.muted = isMuted;
      if (isPlaying) {
        audioRef.current.play().catch(e => console.error("Audio play failed:", e));
      } else {
        audioRef.current.pause();
      }
    }
  }, [isPlaying, currentTrackIdx, isMuted]);

  const togglePlay = () => setIsPlaying(!isPlaying);
  const nextTrack = () => setCurrentTrackIdx((i) => (i + 1) % TRACKS.length);
  const prevTrack = () => setCurrentTrackIdx((i) => (i - 1 + TRACKS.length) % TRACKS.length);
  const toggleMute = () => setIsMuted(!isMuted);

  return (
    <div className="min-h-screen bg-black flex flex-col items-center justify-center p-4 font-mono text-[#00FFFF] crt-flicker">
      <div className="static-bg"></div>
      <div className="scanlines"></div>

      {/* Header */}
      <div className="w-full max-w-lg flex justify-between items-end mb-4 z-10 border-b-4 border-[#FF00FF] pb-2">
        <div>
          <h1 className="text-4xl font-bold tracking-widest glitch" data-text="PROTOCOL:SNAKE">
            PROTOCOL:SNAKE
          </h1>
          <p className="text-[#FF00FF] text-sm tracking-widest mt-1">STATUS: {hasStarted ? (gameOver ? 'TERMINATED' : 'ACTIVE') : 'STANDBY'}</p>
        </div>
        <div className="text-right">
          <p className="text-[#FF00FF] text-sm tracking-widest mb-1">BIOMASS</p>
          <p className="text-3xl font-bold leading-none">
            {score.toString().padStart(4, '0')}
          </p>
        </div>
      </div>

      {/* Game Board */}
      <div className="relative w-full max-w-lg aspect-square bg-black border-4 border-[#00FFFF] p-1 z-10 shadow-[0_0_20px_#00FFFF] tear">
        
        {/* Grid */}
        <div 
          className="w-full h-full grid gap-0"
          style={{ gridTemplateColumns: `repeat(${GRID_SIZE}, minmax(0, 1fr))` }}
        >
          {Array.from({ length: GRID_SIZE * GRID_SIZE }).map((_, i) => {
            const x = i % GRID_SIZE;
            const y = Math.floor(i / GRID_SIZE);
            const isHead = snake[0].x === x && snake[0].y === y;
            const isBody = snake.some((s, idx) => idx !== 0 && s.x === x && s.y === y);
            const isFood = food.x === x && food.y === y;

            return (
              <div 
                key={i} 
                className={`
                  ${isHead ? 'bg-[#00FFFF] border border-black' : ''}
                  ${isBody ? 'bg-[#00FFFF] opacity-80 border border-black' : ''}
                  ${isFood ? 'bg-[#FF00FF] animate-pulse' : ''}
                  ${!isHead && !isBody && !isFood ? 'bg-transparent' : ''}
                `}
              />
            );
          })}
        </div>

        {/* Overlays */}
        {!hasStarted && (
          <div className="absolute inset-0 bg-black/90 flex flex-col items-center justify-center z-20 border-4 border-[#FF00FF] m-4">
            <h2 className="text-3xl text-[#FF00FF] mb-6 glitch" data-text="AWAITING INPUT">AWAITING INPUT</h2>
            <button 
              onClick={startGame}
              className="px-6 py-2 bg-transparent border-2 border-[#00FFFF] text-[#00FFFF] text-xl hover:bg-[#00FFFF] hover:text-black transition-none uppercase cursor-pointer"
            >
              [ EXECUTE_SEQUENCE ]
            </button>
            <p className="text-[#FF00FF] text-sm mt-8">INPUT: WASD / ARROWS</p>
          </div>
        )}

        {gameOver && (
          <div className="absolute inset-0 bg-black/90 flex flex-col items-center justify-center z-20 border-4 border-[#FF00FF] m-4 tear">
            <h2 className="text-4xl text-[#FF00FF] mb-2 glitch" data-text="FATAL_ERROR">FATAL_ERROR</h2>
            <p className="text-[#00FFFF] mb-8 text-xl">ENTITY_TERMINATED</p>
            <button 
              onClick={resetGame} 
              className="px-6 py-2 bg-transparent border-2 border-[#FF00FF] text-[#FF00FF] text-xl hover:bg-[#FF00FF] hover:text-black transition-none uppercase cursor-pointer"
            >
              [ REBOOT ]
            </button>
          </div>
        )}

        {isPaused && hasStarted && !gameOver && (
          <div className="absolute inset-0 bg-black/80 flex items-center justify-center z-20">
            <h2 className="text-4xl text-[#00FFFF] glitch" data-text="SYSTEM_PAUSED">SYSTEM_PAUSED</h2>
          </div>
        )}
      </div>

      {/* Music Player */}
      <div className="mt-6 w-full max-w-lg bg-black border-2 border-[#FF00FF] p-4 z-10 shadow-[0_0_15px_#FF00FF]">
        <div className="flex justify-between items-start mb-4 border-b-2 border-[#00FFFF] pb-2">
          <div>
            <h3 className="text-[#FF00FF] text-sm tracking-widest mb-1">AUDIO_FEED</h3>
            <p className="text-xl truncate max-w-[250px] glitch" data-text={TRACKS[currentTrackIdx].title}>
              {TRACKS[currentTrackIdx].title}
            </p>
          </div>
          <div className="text-right">
            <p className="text-[#FF00FF] text-sm tracking-widest mb-1">STATE</p>
            <p className="text-lg">{isPlaying ? 'TRANSMITTING' : 'HALTED'}</p>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex gap-4">
            <button onClick={prevTrack} className="text-[#00FFFF] hover:text-[#FF00FF] hover:bg-[#00FFFF]/20 px-2 py-1 border border-transparent hover:border-[#FF00FF] cursor-pointer">
              [ &lt;&lt; ]
            </button>
            <button 
              onClick={togglePlay} 
              className="text-[#FF00FF] hover:text-black hover:bg-[#FF00FF] px-4 py-1 border border-[#FF00FF] cursor-pointer"
            >
              {isPlaying ? '[ PAUSE ]' : '[ PLAY ]'}
            </button>
            <button onClick={nextTrack} className="text-[#00FFFF] hover:text-[#FF00FF] hover:bg-[#00FFFF]/20 px-2 py-1 border border-transparent hover:border-[#FF00FF] cursor-pointer">
              [ &gt;&gt; ]
            </button>
          </div>
          
          <button onClick={toggleMute} className="text-[#00FFFF] hover:text-[#FF00FF] border border-transparent hover:border-[#FF00FF] px-2 py-1 cursor-pointer">
            {isMuted ? '[ MUTED ]' : '[ VOL: ON ]'}
          </button>
        </div>

        <audio 
          ref={audioRef} 
          src={TRACKS[currentTrackIdx].url} 
          onEnded={nextTrack}
          autoPlay={isPlaying}
        />
      </div>
    </div>
  );
}
