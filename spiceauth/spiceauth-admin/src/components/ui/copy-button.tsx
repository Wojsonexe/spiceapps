'use client';

import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Button } from './button';
import { toast } from 'sonner';

interface CopyButtonProps {
    value: string;
    label?: string;
}

export function CopyButton({ value, label = 'Copy' }: CopyButtonProps) {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        toast.success('Copied to clipboard');
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-8 gap-2"
        >
            {copied ? (
                <>
                    <Check className="h-4 w-4" />
                    Copied
                </>
            ) : (
                <>
                    <Copy className="h-4 w-4" />
                    {label}
                </>
            )}
        </Button>
    );
}
