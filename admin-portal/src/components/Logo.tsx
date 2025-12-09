interface LogoProps {
  className?: string
  iconOnly?: boolean
  monochrome?: boolean
}

export default function Logo({ className = 'h-8', iconOnly = false, monochrome = false }: LogoProps) {
  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="h-full w-auto"
        aria-label="Hexalgon Logo"
      >
        <defs>
          <filter id="dropshadow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="4" stdDeviation="4" floodOpacity="0.3"/>
          </filter>
        </defs>

        {/* Background Hexagon */}
        <path
          d="M50 5 L93.3 30 V80 L50 105 L6.7 80 V30 L50 5Z"
          fill={monochrome ? "currentColor" : "#0891b2"} 
          stroke={monochrome ? "currentColor" : "#06b6d4"}
          strokeWidth={monochrome ? "2" : "0"}
          className={monochrome ? "opacity-20" : ""}
        />

        {/* Inner Security Mechanism */}
        {monochrome ? (
          <g stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" className="opacity-40">
            <path d="M50 25 V45" />
            <path d="M50 65 V85" />
            <path d="M30 55 L70 55" />
            <circle cx="50" cy="55" r="12" />
          </g>
        ) : (
          <g filter="url(#dropshadow)">
            {/* Vertical Locking Bar */}
            <path 
              d="M44 25 H56 V43.5 C59.5 44.8 62 48.1 62 52 C62 57.5 57.5 62 52 62 H48 C42.5 62 38 57.5 38 52 C38 48.1 40.5 44.8 44 43.5 V25Z" 
              fill="white" 
            />
            
            {/* Horizontal Access Nodes */}
            <circle cx="25" cy="52" r="5" fill="white" />
            <circle cx="75" cy="52" r="5" fill="white" />
            
            {/* Connecting Circuits */}
            <path d="M30 52 H38" stroke="white" strokeWidth="3" strokeLinecap="round" opacity="0.9"/>
            <path d="M62 52 H70" stroke="white" strokeWidth="3" strokeLinecap="round" opacity="0.9"/>
          </g>
        )}
      </svg>
      
      {!iconOnly && (
        <div className="flex flex-col justify-center">
          <span className={`font-bold text-xl tracking-tight ${monochrome ? 'text-current' : 'text-white'}`}>
            Hexalgon
          </span>
        </div>
      )}
    </div>
  )
}

export function LogoMark({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 100 100"
      className={`${className} text-hex-500`}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <filter id="dropshadow-mark" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="4" stdDeviation="4" floodOpacity="0.3"/>
        </filter>
      </defs>
      <path
        d="M50 5 L93.3 30 V80 L50 105 L6.7 80 V30 L50 5Z"
        fill="#0891b2"
        stroke="#06b6d4"
        strokeWidth="0"
      />
      <g filter="url(#dropshadow-mark)">
        <path 
          d="M44 25 H56 V43.5 C59.5 44.8 62 48.1 62 52 C62 57.5 57.5 62 52 62 H48 C42.5 62 38 57.5 38 52 C38 48.1 40.5 44.8 44 43.5 V25Z" 
          fill="white" 
        />
        <circle cx="25" cy="52" r="5" fill="white" />
        <circle cx="75" cy="52" r="5" fill="white" />
        <path d="M30 52 H38" stroke="white" strokeWidth="3" strokeLinecap="round" opacity="0.9"/>
        <path d="M62 52 H70" stroke="white" strokeWidth="3" strokeLinecap="round" opacity="0.9"/>
      </g>
    </svg>
  )
}
