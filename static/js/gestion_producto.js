// static/js/gestion_producto.js

document.addEventListener('DOMContentLoaded', function() {
    const selectUbicacion = document.getElementById('ubicacion_actual');
    const selectContainer = document.getElementById('ubicacion_select_container');

    if (!selectUbicacion || !selectContainer) {
        return;
    }

    // Obtenemos el valor inicial de la ubicación 'otra' desde el atributo data-
    const initialOtraUbicacionValue = selectUbicacion.dataset.initialValue || ''; 

    function createOtraUbicacionDiv() {
        const div = document.createElement('div');
        div.id = 'otra_ubicacion_div_injected';
        div.className = 'mb-3';

        div.innerHTML = `
            <label for="otra_ubicacion_actual" class="form-label">Especificar otra ubicación (ej. Mesa 3, Campana de Extracción):</label>
            <input type="text" class="form-control" id="otra_ubicacion_actual" name="otra_ubicacion_actual"
                   value="${initialOtraUbicacionValue}">
        `;
        return div;
    }

    function actualizarVisibilidad() {
        const currentValue = selectUbicacion.value.toLowerCase().trim();
        const isOtro = currentValue === 'otro';
        let injectedDiv = document.getElementById('otra_ubicacion_div_injected');

        if (isOtro) {
            if (!injectedDiv) {
                const newDiv = createOtraUbicacionDiv();
                selectContainer.insertAdjacentElement('afterend', newDiv);
            }
        } else {
            if (injectedDiv) {
                injectedDiv.remove();
            }
        }
    }

    selectUbicacion.addEventListener('change', actualizarVisibilidad);
    actualizarVisibilidad(); 
});