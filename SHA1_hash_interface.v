module SHA1_hash (       
	clk, 		
	nreset, 	
	start_hash,  
	message_addr,	
	message_size, 	
	hash, 	
	done, 		
	port_A_clk,
        port_A_data_in,
        port_A_data_out,
        port_A_addr,
        port_A_we
	);

input	clk;
input	nreset; 
// Initializes the SHA1_hash module

input	start_hash; 
// Tells SHA1_hash to start hashing the given frame

input 	[31:0] message_addr; 
// Starting address of the messagetext frame
// i.e., specifies from where SHA1_hash must read the messagetext frame

input	[31:0] message_size; 
// Length of the message in bytes

output	[159:0] hash; 
// hash results


input   [31:0] port_A_data_out; 
// read data from the dpsram (messagetext)

output  [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output  [15:0] port_A_addr;
// address of dpsram being read/written 

output  port_A_clk;
// clock to dpsram (drive this with the input clk) 

output  port_A_we;
// read/write selector for dpsram

output	done; // done is a signal to indicate that hash  is complete

//I began coding here

//initialize constants
parameter H_0 = 32'h67452301;
parameter H_1 = 32'hefcdab89;
parameter H_2 = 32'h98badcfe;
parameter H_3 = 32'h10325476;
parameter H_4 = 32'hc3d2e1f0;

//H registers
reg[31:0] H0 = H_0;
reg[31:0] H1 = H_1;
reg[31:0] H2 = H_2;
reg[31:0] H3 = H_3;
reg[31:0] H4 = H_4;

//Create Constants
parameter k_0_19 = 32'h5a827999;
parameter k_20_39 = 32'h6ed9eba1;
parameter k_40_59 = 32'h8f1bbcdc;
parameter k_60_79 = 32'hca62c1d6;
//register for kt
reg[31:0] kt;
wire[31:0] T; //register for value ot T

//registers for round A-E values
reg[31:0] A = H_0;
reg[31:0] B = H_1;
reg[31:0] C = H_2;
reg[31:0] D = H_3;
reg[31:0] E = H_4;

//register for function TODO
//wire[31:0] f;
//used to create function values
//wire[31:0] f1, f2, f3;

//register for function
reg[31:0] f;
//used to create function values
reg[31:0] f1, f2, f3;


//change endian function
function [31:0] changeEndian;
    input [31:0] val;
    changeEndian = {val[7:0], val[15:8], val[23:16], val[31:24]};
endfunction

//rotate left function
function [31:0] rotl;
    input [31:0] val;
    input [31:0] ramt;
    rotl = (val << ramt) | (val >> 32 - ramt);
endfunction
//looping logic reg
reg [7:0] loop = 0;
reg fin;

//create registers for w[i] values
reg [31:0] w[0:79];
reg final_chunk = 0; //used to determine the final message chunk
reg [15:0] read_amt = 16'd0; //used to check which address to read from (in bytes)
reg [31:0] wt;


//reg to signal complete
reg final_flag = 1'd0;
reg real_final_flag = 1'd0;

//process these values
always @(posedge clk) begin
    if(loop == 80) begin
        read_amt <= read_amt + 3'd4;
    end
    if(loop < 16) begin
        if(read_amt <= message_size & final_chunk == 0) begin //if we're not at the final chunk yet
           w[loop] <= changeEndian(port_A_data_out); //loop < 16, w[t] = just the 32 bits of the message
           if(loop != 15) begin
                read_amt <= read_amt + 3'd4; //increment by bytes
           end
        end
        else if(read_amt > message_size & final_chunk == 0) begin //if we're in the final chunk and past the message size
            final_chunk <= 1; //flag for final chunk
            if(message_size % 4 == 1) begin
                w[loop] <= changeEndian(port_A_data_out) | 32'h00800000;
            end
            else if(message_size % 4 == 2) begin
                w[loop] <= changeEndian(port_A_data_out) | 32'h00008000;
            end
            else if(message_size % 4 == 3) begin
                w[loop] <= changeEndian(port_A_data_out) | 32'h00000080;
            end
            else begin //message_size % 4 == 0
                w[loop] <= 32'h80000000;
            end
        end
        else if(final_chunk == 1) begin //we're at the final chunk and we've already padded a 1
            w[loop] <= 32'h00000000;
            if(loop == 15 & fin) begin //if we're on the 15'th loop pad the message size
                w[15] <= message_size << 3;
                final_flag <= 1'd1;
            end
        end
    end
    else if(loop >= 16) begin
         w[loop] <= rotl((w[loop-3] ^ w[loop-8] ^ w[loop-14] ^ w[loop-16]), 1); //rotate left 1
    end
end 

always @(posedge clk) begin
    if(loop > 0) begin
        wt <= w[loop-1];
    end
end

//assign T-value
assign T = rotl(A, 5) + f + E + kt + wt;

always@(posedge clk) begin
    if(loop < 21 & loop != 0) begin
        f <= (B&C)^(~B&D);

    end
    else if(loop < 41) begin
        f <= B^C^D;
    end
    else if(loop < 61) begin
        f <= (B&C)^(C&D)^(B&D);
    end
    else begin
        f<= B^C^D;
    end
end


//Create the A-E values
always@(posedge clk) begin
    if(loop == 0) begin
        if(!start_hash) begin
                A <= H0;
                B <= H1;
                C <= H2;
                D <= H3;
                E <= H4;
            end
        end
    else if(loop < 80) begin
            #10;
            E <= D;
            D <= C;
            C <= rotl(B, 30);
            B <= A;
            A <= rotl(A,5) + f + E + kt + wt;//T;
    end
    else if(loop == 80) begin 
        #20
        A <= H0;
        B <= H1;
        C <= H2;
        D <= H3;
        E <= H4;
        if(final_flag) begin
            real_final_flag <= 1'd1;
        end
    end
end

//H0 - H4 updates
always@(posedge clk) begin
    if(loop == 80) begin
        #10;
        H0 <= T + H0;
        H1 <= A + H1;
        H2 <= rotl(B, 30) + H2;
        H3 <= C + H3;
        H4 <= D + H4;
    end
end


//create constants
always @(posedge clk) begin
    if(loop < 20) begin
        #10;
        kt <= k_0_19;
    end
    else if(loop < 40) begin
        #10;
        kt <= k_20_39;
    end
    else if (loop < 60) begin
        #10;
        kt <= k_40_59;
    end
    else begin
        #10;
        kt <= k_60_79;
    end
end


//looping logic
always @(posedge clk) begin
    if (loop == 0 ) begin //if loop hasn't started
        if(!(^port_A_data_out === 1'bX) | final_chunk) begin
            #10;
            loop <= loop + 7'd1;
        end
    end
    else if(loop == 80) begin
        #10;
        loop <= 0;
        if(final_chunk) begin
            fin <= 1'd1;
        end
    end
    else if(loop < 80) begin
        #10;
        loop <= loop + 7'd1;
    end
    else begin
        loop <= 7'd0;
    end
end


//assign done = fin & final_chunk & hash_complete; //assign done output to fin
assign done = real_final_flag;
assign hash = {H0, H1, H2, H3, H4}; //assign finished hash
assign port_A_clk = clk; //assign the clock
assign port_A_we = 1'b0; //we never write anything to DPSRAM
assign port_A_addr = read_amt + message_addr[15:0]; //assign address
assign port_A_data_in = 32'h42042069;


endmodule
