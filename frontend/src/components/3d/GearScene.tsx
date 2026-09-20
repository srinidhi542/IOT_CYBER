import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Float } from '@react-three/drei';
import * as THREE from 'three';

/* ─── Gear Tooth Component ─── */
function Tooth({ angle, radius, width, height, depth }: { angle: number; radius: number; width: number; height: number; depth: number }) {
  const x = Math.cos(angle) * radius;
  const z = Math.sin(angle) * radius;
  return (
    <mesh position={[x, 0, z]} rotation={[0, -angle, 0]}>
      <boxGeometry args={[width, height, depth]} />
      <meshStandardMaterial
        color="#38bdf8"
        emissive="#0284c7"
        emissiveIntensity={1.2}
        metalness={0.85}
        roughness={0.15}
      />
    </mesh>
  );
}

/* ─── Isometric Sci-Fi Gear Assembly ─── */
function SciFiGear() {
  const gearGroupRef = useRef<THREE.Group>(null!);
  const hubRef = useRef<THREE.Mesh>(null!);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (gearGroupRef.current) {
      gearGroupRef.current.rotation.y = t * 0.45;
    }
    if (hubRef.current) {
      hubRef.current.rotation.y = -t * 0.8;
    }
  });

  const TEETH_COUNT = 10;
  const RADIUS = 0.82;

  return (
    <group position={[0, 0.45, 0]}>
      <Float speed={1.5} rotationIntensity={0.08} floatIntensity={0.3}>
        <group ref={gearGroupRef}>
          {/* Main Gear Ring Rim */}
          <mesh castShadow receiveShadow>
            <torusGeometry args={[RADIUS, 0.16, 24, 48]} />
            <meshStandardMaterial
              color="#0284c7"
              emissive="#0369a1"
              emissiveIntensity={1.0}
              metalness={0.9}
              roughness={0.12}
            />
          </mesh>

          {/* 10 Precision Gear Teeth */}
          {Array.from({ length: TEETH_COUNT }, (_, i) => {
            const angle = (i / TEETH_COUNT) * Math.PI * 2;
            return (
              <Tooth
                key={i}
                angle={angle}
                radius={RADIUS + 0.16}
                width={0.16}
                height={0.28}
                depth={0.14}
              />
            );
          })}

          {/* Central Axle Hub */}
          <mesh ref={hubRef} castShadow>
            <cylinderGeometry args={[0.32, 0.32, 0.38, 24]} />
            <meshStandardMaterial
              color="#00e5ff"
              emissive="#0284c7"
              emissiveIntensity={1.5}
              metalness={0.7}
              roughness={0.2}
            />
          </mesh>

          {/* Central Hole Ring */}
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[0.34, 0.03, 16, 32]} />
            <meshStandardMaterial color="#67e8f9" emissive="#00e5ff" emissiveIntensity={2.5} />
          </mesh>

          {/* 4 Connecting Spoke Rods */}
          {[0, Math.PI / 2, Math.PI, (3 * Math.PI) / 2].map((angle, idx) => (
            <mesh
              key={idx}
              position={[Math.cos(angle) * (RADIUS / 2), 0, Math.sin(angle) * (RADIUS / 2)]}
              rotation={[0, -angle, Math.PI / 2]}
            >
              <cylinderGeometry args={[0.035, 0.035, RADIUS * 0.9, 12]} />
              <meshStandardMaterial color="#38bdf8" emissive="#0284c7" emissiveIntensity={1.1} />
            </mesh>
          ))}

          {/* Center Light */}
          <pointLight color="#00e5ff" intensity={3} distance={4} />
          <pointLight color="#3b82f6" intensity={2} distance={5} position={[0, 0, -0.4]} />
        </group>
      </Float>
    </group>
  );
}

/* ─── Cyber Pedestal with Multi-Tier Rings ─── */
function GearPedestal() {
  const outerRingRef = useRef<THREE.Mesh>(null!);
  const midRingRef = useRef<THREE.Mesh>(null!);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    if (outerRingRef.current) outerRingRef.current.rotation.z = t * 0.35;
    if (midRingRef.current) midRingRef.current.rotation.z = -t * 0.55;
  });

  return (
    <group position={[0, -1.35, 0]}>
      {/* Tier 1 Base */}
      <mesh position={[0, -0.25, 0]}>
        <cylinderGeometry args={[1.5, 1.7, 0.18, 48]} />
        <meshStandardMaterial color="#040914" emissive="#021d3a" emissiveIntensity={0.3} metalness={0.9} roughness={0.2} />
      </mesh>

      {/* Tier 2 Middle Step */}
      <mesh position={[0, -0.08, 0]}>
        <cylinderGeometry args={[1.25, 1.38, 0.18, 48]} />
        <meshStandardMaterial color="#061224" emissive="#0284c7" emissiveIntensity={0.25} metalness={0.85} roughness={0.25} />
      </mesh>

      {/* Tier 3 Upper Platform */}
      <mesh position={[0, 0.06, 0]}>
        <cylinderGeometry args={[1.0, 1.1, 0.12, 48]} />
        <meshStandardMaterial color="#091b33" emissive="#00e5ff" emissiveIntensity={0.4} metalness={0.8} roughness={0.3} />
      </mesh>

      {/* Glowing Neon Ring 1 */}
      <mesh ref={outerRingRef} position={[0, -0.16, 0]} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[1.52, 0.022, 16, 64]} />
        <meshStandardMaterial color="#00e5ff" emissive="#00e5ff" emissiveIntensity={2.5} />
      </mesh>

      {/* Glowing Neon Ring 2 */}
      <mesh ref={midRingRef} position={[0, 0.01, 0]} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[1.26, 0.022, 16, 64]} />
        <meshStandardMaterial color="#38bdf8" emissive="#0284c7" emissiveIntensity={2.2} />
      </mesh>

      {/* Glowing Platform Top Ring */}
      <mesh position={[0, 0.13, 0]} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[0.92, 0.018, 16, 48]} />
        <meshStandardMaterial color="#60a5fa" emissive="#00e5ff" emissiveIntensity={3} />
      </mesh>

      {/* Upward Light Beam */}
      <pointLight position={[0, 0.35, 0]} color="#00e5ff" intensity={3.5} distance={3} />
    </group>
  );
}

/* ─── Orbiting Ambient Glow Particles ─── */
function OrbitParticles() {
  const groupRef = useRef<THREE.Group>(null!);
  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.rotation.y = -state.clock.elapsedTime * 0.2;
    }
  });

  const particles = useMemo(() => {
    return Array.from({ length: 16 }, (_, i) => {
      const angle = (i / 16) * Math.PI * 2;
      const radius = 1.35 + (i % 3) * 0.25;
      const y = ((i % 4) - 1.5) * 0.4;
      return [Math.cos(angle) * radius, y, Math.sin(angle) * radius] as [number, number, number];
    });
  }, []);

  return (
    <group ref={groupRef}>
      {particles.map((pos, idx) => (
        <mesh key={idx} position={pos}>
          <sphereGeometry args={[0.022, 8, 8]} />
          <meshStandardMaterial color="#00e5ff" emissive="#00e5ff" emissiveIntensity={3} />
        </mesh>
      ))}
    </group>
  );
}

/* ─── Main Scene Export ─── */
export const GearScene: React.FC = () => {
  return (
    <div className="w-full h-full relative" style={{ minHeight: 360 }}>
      <Canvas
        camera={{ position: [0, 0.4, 4.6], fov: 42, near: 0.1, far: 30 }}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
        dpr={[1, 2]}
      >
        <ambientLight color="#020d20" intensity={0.7} />
        <directionalLight position={[4, 7, 5]} color="#0284c7" intensity={0.8} />
        <directionalLight position={[-4, -2, -3]} color="#38bdf8" intensity={0.5} />

        <SciFiGear />
        <GearPedestal />
        <OrbitParticles />

        <fog attach="fog" args={['#01030a', 6, 14]} />
      </Canvas>
    </div>
  );
};
