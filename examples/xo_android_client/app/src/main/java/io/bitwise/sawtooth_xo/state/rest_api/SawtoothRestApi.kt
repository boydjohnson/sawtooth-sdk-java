package io.bitwise.sawtooth_xo.state.rest_api

import retrofit2.Call
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

interface SawtoothRestApi {

    @POST("/batches")
    fun postBatchList(payload: ByteArray): Call<BatchListResponse>

    @GET("/batch_statuses")
    fun getBatchStatus(@Query("batch_id") batch_id: String) Call<>
}