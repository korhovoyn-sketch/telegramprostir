'use client'

import { useEffect, useRef } from 'react'

const COLORS = ['#7AB3FF', '#A87CFF', '#FF7AB8', '#34C759', '#FFD700', '#FF9500']

interface Piece {
  x: number
  y: number
  vx: number
  vy: number
  color: string
  rotation: number
  rotationSpeed: number
  width: number
  height: number
}

export default function Confetti() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    canvas.width = window.innerWidth
    canvas.height = window.innerHeight

    const pieces: Piece[] = Array.from({ length: 60 }, () => ({
      x: Math.random() * canvas.width,
      y: -10 - Math.random() * 100,
      vx: (Math.random() - 0.5) * 4,
      vy: 2 + Math.random() * 3,
      color: COLORS[Math.floor(Math.random() * COLORS.length)],
      rotation: Math.random() * Math.PI * 2,
      rotationSpeed: (Math.random() - 0.5) * 0.2,
      width: 6 + Math.random() * 6,
      height: 4 + Math.random() * 4,
    }))

    let frame: number
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      pieces.forEach((p) => {
        p.x += p.vx
        p.y += p.vy
        p.rotation += p.rotationSpeed
        p.vy += 0.05

        ctx.save()
        ctx.translate(p.x, p.y)
        ctx.rotate(p.rotation)
        ctx.fillStyle = p.color
        ctx.fillRect(-p.width / 2, -p.height / 2, p.width, p.height)
        ctx.restore()
      })
      pieces.forEach((p) => {
        if (p.y > canvas.height + 20) {
          p.y = -10
          p.x = Math.random() * canvas.width
        }
      })
      frame = requestAnimationFrame(animate)
    }
    animate()

    const timer = setTimeout(() => cancelAnimationFrame(frame), 4000)
    return () => {
      clearTimeout(timer)
      cancelAnimationFrame(frame)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 25 }}
    />
  )
}
