document.addEventListener('DOMContentLoaded', function() {
    const selectUbicacion = document.getElementById('ubicacion_actual');
    const contenedorOtro = document.getElementById('otroUbicacionContainer');
    const inputOtro = document.getElementById('otra_ubicacion_actual');

    function actualizarCampoOtro() {
        const valor = (selectUbicacion.value || '').toLowerCase().trim();
        if (valor === 'otro') {
            contenedorOtro.classList.remove('d-none');
            inputOtro.required = true;
        } else {
            contenedorOtro.classList.add('d-none');
            inputOtro.required = false;
            inputOtro.value = '';
        }
    }

    actualizarCampoOtro();
    selectUbicacion.addEventListener('change', actualizarCampoOtro);
});
