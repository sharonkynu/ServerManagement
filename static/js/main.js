// Main JavaScript functionality for Server Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips and interactive elements
    initializeTooltips();
    initializeAnimations();
    initializeFormValidation();
    initializeThemeToggle();
});

// Tooltip functionality
function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(event) {
    const element = event.target;
    const tooltipText = element.getAttribute('data-tooltip');
    
    if (!tooltipText) return;
    
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = tooltipText;
    tooltip.style.cssText = `
        position: absolute;
        background: #1f2937;
        color: white;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 500;
        z-index: 1000;
        pointer-events: none;
        opacity: 0;
        transition: opacity 0.2s ease;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    `;
    
    document.body.appendChild(tooltip);
    
    const rect = element.getBoundingClientRect();
    tooltip.style.left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2 + 'px';
    tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
    
    setTimeout(() => {
        tooltip.style.opacity = '1';
    }, 10);
    
    element._tooltip = tooltip;
}

function hideTooltip(event) {
    const element = event.target;
    if (element._tooltip) {
        element._tooltip.style.opacity = '0';
        setTimeout(() => {
            if (element._tooltip && element._tooltip.parentNode) {
                element._tooltip.parentNode.removeChild(element._tooltip);
            }
            delete element._tooltip;
        }, 200);
    }
}

// Animation utilities
function initializeAnimations() {
    // Intersection Observer for scroll animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
            }
        });
    }, observerOptions);
    
    // Observe all cards and sections
    const animateElements = document.querySelectorAll('.dashboard-card, .info-card, .config-card, .status-card');
    animateElements.forEach(el => {
        observer.observe(el);
    });
    
    // Staggered animation for grid items
    const gridItems = document.querySelectorAll('.dashboard-card, .info-card, .config-card');
    gridItems.forEach((item, index) => {
        item.style.animationDelay = `${index * 0.1}s`;
    });
}

// Form validation
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', validateForm);
        
        // Real-time validation for inputs
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('blur', validateField);
            input.addEventListener('input', clearFieldError);
        });
    });
}

function validateForm(event) {
    const form = event.target;
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!validateField({ target: input })) {
            isValid = false;
        }
    });
    
    if (!isValid) {
        event.preventDefault();
        showNotification('Please fix the errors in the form', 'error');
    }
    
    return isValid;
}

function validateField(event) {
    const field = event.target;
    const value = field.value.trim();
    const type = field.type;
    const required = field.hasAttribute('required');
    
    clearFieldError(event);
    
    let isValid = true;
    let errorMessage = '';
    
    // Required field validation
    if (required && !value) {
        isValid = false;
        errorMessage = 'This field is required';
    }
    
    // Type-specific validation
    if (value && isValid) {
        switch (type) {
            case 'email':
                if (!isValidEmail(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid email address';
                }
                break;
            case 'password':
                if (value.length < 6) {
                    isValid = false;
                    errorMessage = 'Password must be at least 6 characters long';
                }
                break;
            case 'number':
                if (isNaN(value) || value < 0) {
                    isValid = false;
                    errorMessage = 'Please enter a valid number';
                }
                break;
            case 'url':
                if (!isValidURL(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid URL';
                }
                break;
        }
    }
    
    // Custom validation for specific fields
    if (value && isValid) {
        const fieldName = field.name;
        switch (fieldName) {
            case 'ip_address':
                if (!isValidIP(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid IP address';
                }
                break;
            case 'port':
                const port = parseInt(value);
                if (port < 1 || port > 65535) {
                    isValid = false;
                    errorMessage = 'Port must be between 1 and 65535';
                }
                break;
            case 'confirm_password':
                const password = document.querySelector('input[name="password"]');
                if (password && value !== password.value) {
                    isValid = false;
                    errorMessage = 'Passwords do not match';
                }
                break;
        }
    }
    
    if (!isValid) {
        showFieldError(field, errorMessage);
    }
    
    return isValid;
}

function showFieldError(field, message) {
    field.classList.add('error');
    
    let errorElement = field.parentNode.querySelector('.field-error');
    if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.className = 'field-error';
        errorElement.style.cssText = `
            color: #ef4444;
            font-size: 12px;
            margin-top: 4px;
            animation: slideDown 0.3s ease-out;
        `;
        field.parentNode.appendChild(errorElement);
    }
    
    errorElement.textContent = message;
}

function clearFieldError(event) {
    const field = event.target;
    field.classList.remove('error');
    
    const errorElement = field.parentNode.querySelector('.field-error');
    if (errorElement) {
        errorElement.remove();
    }
}

// Theme toggle functionality
function initializeThemeToggle() {
    // Check for saved theme preference or default to light mode
    const currentTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    
    // Create theme toggle button if it doesn't exist
    if (!document.querySelector('.theme-toggle')) {
        createThemeToggle();
    }
}

function createThemeToggle() {
    const themeToggle = document.createElement('button');
    themeToggle.className = 'theme-toggle';
    themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
    themeToggle.style.cssText = `
        position: fixed;
        bottom: 30px;
        right: 30px;
        width: 50px;
        height: 50px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        border: none;
        border-radius: 50%;
        color: white;
        font-size: 18px;
        cursor: pointer;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        transition: all 0.3s ease;
        z-index: 1000;
    `;
    
    themeToggle.addEventListener('click', toggleTheme);
    document.body.appendChild(themeToggle);
    
    // Update icon based on current theme
    updateThemeIcon();
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    updateThemeIcon();
    showNotification(`Switched to ${newTheme} theme`, 'info');
}

function updateThemeIcon() {
    const themeToggle = document.querySelector('.theme-toggle');
    if (!themeToggle) return;
    
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const icon = themeToggle.querySelector('i');
    
    if (currentTheme === 'dark') {
        icon.className = 'fas fa-sun';
    } else {
        icon.className = 'fas fa-moon';
    }
}

// Notification system
function showNotification(message, type = 'info', duration = 3000) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    
    const iconMap = {
        success: 'check-circle',
        error: 'exclamation-triangle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    
    notification.innerHTML = `
        <i class="fas fa-${iconMap[type] || 'info-circle'}"></i>
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Style the notification
    notification.style.cssText = `
        position: fixed;
        top: 100px;
        right: 30px;
        z-index: 1001;
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 16px 20px;
        border-radius: 12px;
        color: white;
        font-weight: 500;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        min-width: 300px;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.3s ease;
        max-width: 400px;
    `;
    
    // Set background based on type
    const colorMap = {
        success: 'linear-gradient(135deg, #10b981, #059669)',
        error: 'linear-gradient(135deg, #ef4444, #dc2626)',
        warning: 'linear-gradient(135deg, #f59e0b, #d97706)',
        info: 'linear-gradient(135deg, #3b82f6, #2563eb)'
    };
    
    notification.style.background = colorMap[type] || colorMap.info;
    
    // Style the close button
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.style.cssText = `
        background: none;
        border: none;
        color: white;
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
        transition: background 0.2s ease;
        margin-left: auto;
    `;
    
    closeBtn.addEventListener('mouseenter', function() {
        this.style.background = 'rgba(255, 255, 255, 0.2)';
    });
    
    closeBtn.addEventListener('mouseleave', function() {
        this.style.background = 'none';
    });
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }
    }, duration);
}

// Loading states
function showLoading(element, text = 'Loading...') {
    if (!element) return;
    
    const originalContent = element.innerHTML;
    element.setAttribute('data-original-content', originalContent);
    element.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
    element.disabled = true;
}

function hideLoading(element) {
    if (!element) return;
    
    const originalContent = element.getAttribute('data-original-content');
    if (originalContent) {
        element.innerHTML = originalContent;
        element.removeAttribute('data-original-content');
    }
    element.disabled = false;
}

// API utilities
async function apiCall(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const config = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, config);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || `HTTP error! status: ${response.status}`);
        }
        
        return data;
    } catch (error) {
        console.error('API call failed:', error);
        showNotification(error.message || 'Network error occurred', 'error');
        throw error;
    }
}

// Utility functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
        return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

function debounce(func, wait, immediate) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            if (!immediate) func(...args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func(...args);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Chart utilities
function createChart(canvasId, config) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    const defaultConfig = {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            }
        }
    };
    
    const finalConfig = { ...defaultConfig, ...config };
    
    try {
        return new Chart(ctx, finalConfig);
    } catch (error) {
        console.error('Chart creation failed:', error);
        return null;
    }
}

// Local storage utilities
function saveToStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (error) {
        console.error('Failed to save to localStorage:', error);
        return false;
    }
}

function loadFromStorage(key, defaultValue = null) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
        console.error('Failed to load from localStorage:', error);
        return defaultValue;
    }
}

function removeFromStorage(key) {
    try {
        localStorage.removeItem(key);
        return true;
    } catch (error) {
        console.error('Failed to remove from localStorage:', error);
        return false;
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Ctrl/Cmd + K for search (if search functionality exists)
    if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
        event.preventDefault();
        const searchInput = document.querySelector('.search-input');
        if (searchInput) {
            searchInput.focus();
        }
    }
    
    // Escape key to close modals
    if (event.key === 'Escape') {
        const openModal = document.querySelector('.modal[style*="block"]');
        if (openModal) {
            openModal.style.display = 'none';
        }
    }
    
    // Ctrl/Cmd + S to save forms
    if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        const activeForm = document.querySelector('form:focus-within');
        if (activeForm) {
            activeForm.dispatchEvent(new Event('submit'));
        }
    }
});

// Auto-save functionality for forms
function initializeAutoSave(formId, interval = 30000) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, select, textarea');
    const storageKey = `autosave_${formId}`;
    
    // Load saved data
    const savedData = loadFromStorage(storageKey);
    if (savedData) {
        Object.keys(savedData).forEach(key => {
            const input = form.querySelector(`[name="${key}"]`);
            if (input) {
                input.value = savedData[key];
            }
        });
    }
    
    // Save data on input change
    const saveData = debounce(() => {
        const formData = new FormData(form);
        const data = {};
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
        saveToStorage(storageKey, data);
    }, 1000);
    
    inputs.forEach(input => {
        input.addEventListener('input', saveData);
    });
    
    // Clear saved data on successful submit
    form.addEventListener('submit', () => {
        removeFromStorage(storageKey);
    });
}

// Error handling
window.addEventListener('error', function(event) {
    console.error('Global error:', event.error);
    showNotification('An unexpected error occurred', 'error');
});

window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification('A network error occurred', 'error');
    event.preventDefault();
});

// Performance monitoring
function measurePerformance(name, fn) {
    const start = performance.now();
    const result = fn();
    const end = performance.now();
    
    console.log(`${name} took ${end - start} milliseconds`);
    return result;
}

// Export functions for global use
window.showNotification = showNotification;
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.apiCall = apiCall;
window.formatBytes = formatBytes;
window.formatUptime = formatUptime;
window.debounce = debounce;
window.throttle = throttle;
window.createChart = createChart;
window.saveToStorage = saveToStorage;
window.loadFromStorage = loadFromStorage;
window.removeFromStorage = removeFromStorage;
window.initializeAutoSave = initializeAutoSave;
window.measurePerformance = measurePerformance;
